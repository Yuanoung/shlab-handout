/* 
 * tsh - A tiny shell program with job control
 * 
 * <Put your name and login ID here>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE 1024   /* max line size */
#define MAXARGS 128    /* max args on a command line */
#define MAXJOBS 16     /* max jobs at any point in time */
#define MAXJID 1 << 16 /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;   /* defined in libc */
char prompt[] = "tsh> "; /* command line prompt (DO NOT CHANGE) */
int verbose = 0;         /* if true, print additional output */
int nextjid = 1;         /* next job ID to allocate */
char sbuf[MAXLINE];      /* for composing sprintf messages */

struct job_t
{                          /* The job struct */
    pid_t pid;             /* job PID */
    int jid;               /* job ID [1, 2, ...] */
    int state;             /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE]; /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */

/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv);
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid);
int updatejob(struct job_t *jobs, pid_t pid, int state);

pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
pid_t jid2pid(int jid);
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv)
{
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF)
    {
        switch (c)
        {
        case 'h': /* print help message */
            usage();
            break;
        case 'v': /* emit additional diagnostic info */
            verbose = 1;
            break;
        case 'p':            /* don't print a prompt */
            emit_prompt = 0; /* handy for automatic testing */
            break;
        default:
            usage();
        }
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT, sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler); /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler); /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler);

    /* Initialize the job list */
    initjobs(jobs);

    /* Execute the shell's read/eval loop */
    while (1)
    {

        /* Read command line */
        if (emit_prompt)
        {
            printf("%s", prompt);
            fflush(stdout);
        }
        /*
         * fgets返回NULL，有2中可能:
         * 
         *      1. 发送错误，通过ferror函数来检查
         *      2. 读到了文件的结尾
         */
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");
        if (feof(stdin))
        { /* End of file (ctrl-d) */
            fflush(stdout);
            exit(0);
        }

        /* Evaluate the command line */
        eval(cmdline);
        fflush(stdout);
        fflush(stdout);
    }

    exit(0); /* control never reaches here */
}

/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline)
{
    char *argv[MAXARGS]; /* argv for execve() */
    int bg;              /* should the job run in bg or fg? */
    pid_t pid;           /* process id */

    /* parse command line */
    bg = parseline(cmdline, argv);
    if (argv[0] == NULL)
        return; /* ignore empty lines */
    if (!strcmp(argv[0], "quit"))
        exit(0); /* terminate shell */

    if (!builtin_command(argv))
    {

        if ((pid = fork()) == 0)
        { /* child */

            /* Background jobs should ignore SIGINT (ctrl-c)  */
            /* and SIGTSTP (ctrl-z) */
            if (bg)
            {
                Signal(SIGINT, SIG_IGN);
                Signal(SIGTSTP, SIG_IGN);
            }

            if (execve(argv[0], argv, environ) < 0)
            {
                printf("%s: Command not found.\n", argv[0]);
                fflush(stdout);
                exit(0);
            }
        }

        /* parent waits for foreground job to terminate or stop */
        addjob(jobs, pid, (bg == 1 ? BG : FG), cmdline);
        if (!bg)
            waitfg(pid);
        else
            printf("%d %s", pid, cmdline);
    }
    return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv)
{
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf) - 1] = ' ';   /* 替换末尾的换行符 \n */
    while (*buf && (*buf == ' ')) /* 跳过前面多余的空格 */
        buf++;

    argc = 0;
    if (*buf == '\'')
    {
        buf++;
        delim = strchr(buf, '\'');
    }
    else
    {
        delim = strchr(buf, ' ');
    }

    while (delim)
    {
        argv[argc++] = buf;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && (*buf == ' ')) /* ignore spaces */
            buf++;

        if (*buf == '\'')
        {
            buf++;
            delim = strchr(buf, '\'');
        }
        else
        {
            delim = strchr(buf, ' ');
        }
    }
    argv[argc] = NULL;

    if (argc == 0) /* ignore blank line */
        return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc - 1] == '&')) != 0)
    {
        argv[--argc] = NULL;
    }
    return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_command(char **argv)
{
    char *cmd = argv[0];

    /* jobs command */
    if (!strcmp(cmd, "jobs"))
    {
        listjobs(jobs);
        return 1;
    }

    /* bg and fg commands */
    if (!strcmp(cmd, "bg") || !strcmp(cmd, "fg"))
    {
        int pid;
        int jid;
        struct job_t *jobp;

        /* ignore command if no argument */
        if (argv[1] == NULL)
        {
            printf("%s command needs PID or %%jid argument\n", cmd);
            return 1;
        }
        if (argv[1][0] == '%')
        {
            jid = atoi(argv[1] + 1);
            pid = jid2pid(jid);
        }
        else
            pid = atoi(argv[1]);

        if ((jobp = getjobpid(jobs, pid)) != NULL)
        {
            if (!strcmp(cmd, "bg"))
            {
                kill(pid, SIGCONT);       // 发送信号
                updatejob(jobs, pid, BG); // 更新状态
                printf("%d %s", pid, jobs->cmdline);
            }
            if (!strcmp(cmd, "fg"))
            {
                kill(pid, SIGCONT);
                updatejob(jobs, pid, FG);
                waitfg(pid);
            }
        }
        else
            printf("(%s) : No such process\n", argv[1]);

        return 1;
    }

    /* ignore singleton & */
    if (!strcmp(argv[0], "&"))
    {
        return 1;
    }

    /* not a builtin command */
    return 0;
}

/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv)
{
    int pid;
    struct job_t *jobp;
    char *cmd = argv[0];

    pid = atoi(argv[1]);

    if ((jobp = getjobpid(jobs, pid)) != NULL)
    {
        if (!strcmp(cmd, "bg")) /* 针对已停止运行（非终止的）子进程 */
        {
            kill(pid, SIGCONT);
            updatejob(jobs, pid, BG);
        }
        if (!strcmp(cmd, "fg"))
        {
            kill(pid, SIGCONT);
            updatejob(jobs, pid, FG);
            waitfg(pid); // 前台运行，需要等待该子进程停止或在终止
        }
    }

    return;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 * 
 *      #include <sys/types.h>
 *      #include <sys/wait.h>
 * 
 *      pid_t waitpid(pid_t pid, int *statusp, int options)
 *      pid_t wait(int *statusp); ==> waitpid(-1, &statusp, 0);
 * 
 * 1. 判定等待集合的成员
 * 
 *  ·如果pid>0,那么等待集合就是一个单独的子进程,它的进程ID等于pid
 *  ·如果pid=-1,那么等待集合就是由父进程所有的子进程组成的。
 * waitpid函数还支持其他类型的等待集合,包括Unix进程组,对此我们将不做讨论。
 * 
 * 2.修改默认行为
 * 
 * 可以通过将 options 设置为常量 WNOHANG、 WUNTRACED和 WCONTINUED
 * 的各种组合来修改默认行为(注意终止和停止):
 * 
 *  · WNOHANG:如果等待集合中的任何子进程都还没有终止,那么就立即返回(返回
 *    值为0)。默认的行为（没有这个参数）是挂起调用进程,直到有子进程终止。在
 *    等待子进程终止的同时,如果还想做些有用的工作,这个选项会有用。
 * 
 *  · WUNTRACED:挂起调用进程的执行,直到等待集合中的一个进程变成已终止或者
 *    被停止。返回的PID为导致返回的已终止或被停止子进程的PID。默认的行为是只返
 *    回已终止的子进程。当你想要检查已终止和被停止的子进程时,这个选项会有用。
 * 
 *  · WCONTINUED:挂起调用进程的执行,直到等待集合中一个正在运行的进程终止
 *    或等待集合中一个被停止的进程收到 SIGCONT信号重新开始执行。
 * 
 * 可以用或运算把这些选项组合起来。例如:
 * WNOHANG | WUNTRACED:立即返回,如果等待集合中的子进程都没有被停
 * 止或终止,则返回值为0;如果有一个停止或终止,则返回值为该子进程的PID
 * 
 * 3.检查已回收子进程的退出状态
 * 
 * 如果 status参数是非空的,那么 waitpid 就会在 status 中放上关于导致返回的
 * 子进程的状态信息, status 是 status 指向的值。wait.h 头文件定义了解释 status 参
 * 数的几个宏:
 * 
 *  · WIFEXITED(status):如果子进程通过调用exit或者一个返回(return)正常终
 *    止,就返回真
 * 
 *  · WEXITSTATUS(status):返回一个正常终止的子进程的退出状态。只有在
 *    WIFEXITEDO返回为真时,才会定义这个状态。
 * 
 *  · WIFSIGNALED(status):如果子进程是因为一个未被捕获的信号终止的,那么
 *    就返回真
 * 
 *  · WTERMSIG(status):返回导致子进程终止的信号的编号。只有在 WIFSIG-
 *    NALED()返回为真时,才定义这个状态。
 * 
 *  · WIFSTOPPED(status):如果引起返回的子进程当前是停止的,那么就返回真。
 * 
 *  · WSTOPSIG(status):返回引起子进程停止的信号的编号。只有在 WIFSTOPPED()
 *    返回为真时,才定义这个状态WIFCONTINUED(status):如果子进程收到 SIGCONT信号
 *    重新启动,则返回真。
 * 
 * 4.错误条件
 * 
 * 如果调用进程没有子进程,那么 waitpid 返回-1,并且设置 errno 为 ECHILD。如
 * 果 waitpid 函数被一个信号中断,那么它返回-1,并设置 errno 为 EINTR。
 */
void waitfg(pid_t pid)
{
    int status;

    /* wait for FG job to stop (WUNTRACED) or terminate */
    if (waitpid(pid, &status, WUNTRACED) < 0 && errno == EINTR)
        unix_error("waitfg: waitpid error");

    /* FG job has stopped. Change its state in jobs list */
    if (WIFSTOPPED(status))
    {
        sprintf(sbuf, "Job %d stopped by signal", pid);
        psignal(WSTOPSIG(status), sbuf);
        updatejob(jobs, pid, ST);
    }

    /* FG job has terminated. Remove it from job list */
    else
    {
        /* check if job was terminated by an uncaught signal */
        if (WIFSIGNALED(status))
        {
            sprintf(sbuf, "Job %d terminated by signal", pid);
            psignal(WTERMSIG(status), sbuf);
        }
        deletejob(jobs, pid);
        if (verbose)
            printf("waitfg: job %d deleted\n", pid);
    }
}

/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig)
{
    pid_t pid;
    int status;

    if (verbose)
        printf("sigchld_handler: entering \n");

    /* 
     * 回收僵尸进程
     * 
     * WNOHANG这个参数很重要，不然当时没有回收进程时，会阻塞住。
     */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        deletejob(jobs, pid);
        if (verbose)
            printf("sigchld_handler: job %d deleted\n", pid);
    }

    /* 
     * 如果WNOHANG，返回值为0，如果其他错误，则为-1，
     * 并设置errno:
     *      1. 如果调用进程没有子进程,设置 errno 为 ECHILD。
     *      2. 如果 waitpid 函数被一个信号中断,设置 errno 为 EINTR。
     */
    if (!((pid == 0) || (pid == -1 && errno == ECHILD)))
        unix_error("sigchld_handler wait error");

    if (verbose)
        printf("sigchld_handler: exiting\n");

    return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig)
{
    if (verbose)
        printf("sigint_handler: shell caught SIGINT\n");
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig)
{
    if (verbose)
        printf("sigtstp_handler: shell caught SIGTSTP\n");
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job)
{
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs)
{
    int i;

    for (i = 0; i < MAXJOBS; i++)
        clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs)
{
    int i, max = 0;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid > max)
            max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline)
{
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jobs[i].pid == 0)
        {
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++; // update nextjid
            if (nextjid > MAXJOBS)
                nextjid = 1;
            strcpy(jobs[i].cmdline, cmdline);
            if (verbose)
            {
                printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
        }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid)
{
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jobs[i].pid == pid)
        {
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs) + 1;
            return 1;
        }
    }
    return 0;
}

/* updatejob - update the state of a job with PID=pid */
int updatejob(struct job_t *jobs, pid_t pid, int state)
{
    int i;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jobs[i].pid == pid)
        {
            jobs[i].state = state;
            return 1;
        }
    }
    printf("Job %d not found\n", pid);
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs)
{
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid)
{
    int i;

    if (pid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid)
{
    int i;

    if (jid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid)
{
    int i;

    if (pid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
        {
            return jobs[i].jid;
        }
    return 0;
}

pid_t jid2pid(int jid)
{
    int i;
    if (jid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return jobs[i].pid;
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs)
{
    int i;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jobs[i].pid != 0)
        {
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state)
            {
            case BG:
                printf("Running ");
                break;
            case FG:
                printf("Foreground ");
                break;
            case ST:
                printf("Stopped ");
                break;
            default:
                printf("listjobs: Internal error: job[%d].state=%d ",
                       i, jobs[i].state);
            }
            printf("%s", jobs[i].cmdline);
        }
    }
}
/******************************
 * end job list helper routines
 ******************************/

/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void)
{
    printf("Usage: shell [-hvp]\n");
    printf("    -h   print this message\n");
    printf("    -v   print additional diagnostic information\n");
    printf("    -p   do not emit a command prompt\n");
    printf("other command:\n");
    printf("    jobs: Print the job list\n");
    printf("    fg(or bg) %%jid: fg or bg job by jid\n");
    printf("    fg(or bg) pid: fg or bg job by pid\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler)
{
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
        unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig)
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}
