/*
*	dropcan.c
*
*	dropcan container core
*
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>

#define KERNEL_VER_MAJOR	5
#define KERNEL_VER_MINOR	16

struct child_config {
	uid_t	uid;
	int		fd;
	char*	hostname;
	char*	mnt_dir;
	int		argc;
	char**	argv;
};

/**********************/
/*    capabilities    */
/**********************/

/*
*	int drop_capabilities()
*
*	Drop any unneeded, extraneous, and/or overprivileged system capabilities which
*	violate or may violate uid namespacing.
*
*/
int drop_capabilities() {
	/*
	*	Many capabilities not dropped from containers, including
	*	CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_LEASE, CAP_LINUX_IMMUTABLE,
	*	CAP_SYS_PACCT, CAP_IPC_OWNER, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE,
	*	CAP_NET_RAW, CAP_SYS_PTRACE, CAP_KILL, CAP_SETUID, CAPSETGID,
	*	CAP_SETPCAP, CAP_SYS_CHROOT, and CAP_SYS_TTYCONFIG, have been evaluated
	*	as not posing a significant security risk within this use case; however,
	*	dropcan is largely experimental and due to limited resources,
	*	it has not been extensively evaluated for vulnerabilities and is
	*	provided AT YOUR OWN RISK.
	*/
	fprintf(stderr, ">> dropping capabilities...");
	const int dropped_caps[] = {
		CAP_AUDIT_CONTROL,		// allows access to system audit controls
		CAP_AUDIT_READ,			// allows access to read from system audits
		CAP_AUDIT_WRITE,		// allows access to write to system audits
		CAP_BLOCK_SUSPEND,		// allows interfering with system suspend
		CAP_WAKE_ALARM,			// allows interfering with system suspend
		CAP_DAC_READ_SEARCH,	// allows reading arbitrary host files by file_handle brute force
		CAP_FSETID,				// allows privilege escalation through setuid binaries
		CAP_IPC_LOCK,			// allows locking more system memory than normally allowed
		CAP_MAC_ADMIN,			// allows access control settings in Apparmor, SELinux, and SMACK
		CAP_MAC_OVERRIDE,		// allows access control override in Apparmor, SELinux, and SMACK
		CAP_MKNOD,				// allows access to device files and management thereof
		CAP_SETFCAP,			// allows loading and altering external executables
		CAP_SYSLOG,				// allows access to system logs and kernel addresses
		CAP_SYS_ADMIN,			// allows many system administration behaviors
		CAP_SYS_BOOT,			// allows system rebooting
		CAP_SYS_MODULE,			// allows loading, unloading, and removal of kernel modules
		CAP_SYS_NICE,			// allows setting process priorities
		CAP_SYS_RAWIO,			// allows full system memory and I/O access
		CAP_SYS_RESOURCE,		// allows circumventing kernel limits
		CAP_SYS_TIME,			// allows altering system time
	};
	size_t num_dropped = sizeof(dropped_caps) / sizeof(*dropped_caps);
	fprintf(stderr, "bounding...");
	for (size_t i = 0; i < num_dropped; i++) {
		if(prctl(PR_CAPBSET_DROP, dropped_caps[i], 0, 0, 0)) {
			fprintf(stderr, "prctl capability dropping failed: %m\n");
			return 1;
		}
	}
	fprintf(stderr, "inheritable...");
	cap_t caps = NULL;
	if(!(caps = cap_get_proc())
		|| cap_set_flag(caps, CAP_INHERITABLE, num_dropped, dropped_caps, CAP_CLEAR)
		|| cap_set_proc(caps)) {
			fprintf(stderr, "failed clearing inheritable capabilities: %m\n");
			if (caps) cap_free(caps);
			return 1;
	}
	cap_free(caps);
	fprintf(stderr, "done.\n");
	return 0;
}

/****************/
/*    mounts    */
/****************/


/*
*	int pivot_root(const char* new_root, const char* put_old)
*
*	Wrapper for root pivot syscall to swap mount at "/" with another.
*
*/
int pivot_root(const char* new_root, const char* put_old) {
	return syscall(SYS_pivot_root, new_root, put_old);
}

/*
*	int mounts(struct child_config* conf)
*
*	Remount everything in a given child with MS_PRIVATE, making the
*	bind mount invisible outside of the child namespace.
*
*/
int mounts(struct child_config* conf) {
	/*
	*	NOTE: dropcan does NOT package or unpackage containers to maximize
	*	simplicity and code size while minimizing attack surfaces. dropcan
	*	relies on the user in order to ensure the namespaced mount
	*	directory doesn't contain trusted/sensitive files or hard links.
	*/
	fprintf(stderr, ">> remounting child namespace with MS_PRIVATE...");
	if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		fprintf(stderr, "remount failed: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, ">> creating temp directory and bind mount...");
	char mnt_dir[] = "/tmp/tmp.XXXXXX";
	if(!mkdtemp(mnt_dir)) {
		fprintf(stderr, "failed making temp directory\n");
		return -1;
	}
	if(mount(conf->mnt_dir, mnt_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
		fprintf(stderr, "bind mount failed\n");
		return -1;
	}

	char inner_mnt_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
	memcpy(inner_mnt_dir, mnt_dir, sizeof(mnt_dir) - 1);
	if(!mkdtemp(inner_mnt_dir)) {
		fprintf(stderr, "failed making inner temp directory\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, ">> pivoting root...");
	if(pivot_root(mnt_dir, inner_mnt_dir)) {
		fprintf(stderr, "failed\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	char* old_root_dir = basename(inner_mnt_dir);
	char old_root[sizeof(inner_mnt_dir) + 1] = {"/"};
	strcpy(&old_root[1], old_root_dir);

	fprintf(stderr, ">> unmounting old root %s...", old_root);
	if(chdir("/")) {
		fprintf(stderr, "chdir failed: %m\n");
		return -1;
	}
	if(umount2(old_root, MNT_DETACH)) {
		fprintf(stderr, "umount failed: %m\n");
		return -1;
	}
	if(rmdir(old_root)) {
		fprintf(stderr, "rmdir failed: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}


/******************/
/*    syscalls    */
/******************/


#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

/*
*	int filter_syscalls()
*
*	Configure filtering of system calls that may lead to 
*	sandbox escapes or other harm.
*
*/
int filter_syscalls() {
	/*
	*	Many syscalls not filtered from use in containers, including _sysctl,
	*	alloc_hugepages, free_hugepages, bdflush, create_module, nfsservctl,
	*	perfctr, get_kernel_syms, setup, clock_adjtime, clock_settime, adjtime,
	*	pciconfig_read, pciconfig_write, quotactl, get_mempolicy, getpagesize,
	*	pciconfig_iobase, ustat, sysfs, uselib, sync_file_range2, readdir,
	*	kexec_file_load, kexec_load, nice, oldfstat, oldlstat, oldolduname, oldstat,
	*	olduname, perfmonctl, ppc_rtas, spu_create, spu_run, subpage_prot,
	*	utrap_install, kern_features, pivot_root, preadv2, and pwritev2 have been 
	*	evaluated as not posing a significant security risk within this use case
	*	given the targeted Linux version(s) & architecture as well as the container
	*	capabilities set previously; however, dropcan is largely experimental and 
	*	due to limited resources, it has not been extensively evaluated
	*	for vulnerabilities and is provided AT YOUR OWN RISK.
	*/
	scmp_filter_ctx ctx = NULL;
	fprintf(stderr, ">> filtering syscalls...");
	if(!(ctx = seccomp_init(SCMP_ACT_ALLOW))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,						// disable creation of new setuid/setgid executables
					SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,						// disable creation of new setuid/setgid executables
					SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,					// disable creation of new setuid/setgid executables
					SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,					// disable creation of new setuid/setgid executables
					SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,					// disable creation of new setuid/setgid executables
					SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,					// disable creation of new setuid/setgid executables
					SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,					// disable nested user namespaces
					SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,						// disable nested user namespaces
					SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,						// disable contained processes writing to the host terminal
					SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI))
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0)					// disable access to kernel keyring system
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0)					// disable access to kernel keyring system
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0)				// disable access to kernel keyring system
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)					// disable ptrace from breaking seccomp
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0)						// disable access to assigning NUMA nodes
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0)				// disable access to assigning NUMA nodes
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0)				// disable access to assigning NUMA nodes
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0)				// disable access to assigning NUMA nodes
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)				// disable unprivileged handling of page faults
		|| seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)			// disable discovery of kernel addresses and uninitialized memory
		|| seccomp_rule_add(ctx, SCMP_FLTATR_CTL_NNP, 0)							// disable setuid and setcap binaries from being executed with their additional privileges
		|| seccomp_load(ctx)) {
			if(ctx) seccomp_release(ctx);
			fprintf("failed to apply filters: %m\n");
			return 1;
		}
		seccomp_release(ctx);
		fprintf(stderr, "done.\n");
		return 0;
}

/*******************/
/*    resources    */
/*******************/

/***********************/
/*        child        */
/***********************/


#define USERNS_OFFSET	10000
#define USERNS_COUNT	2000

/*
* 	int handle_child_uid_map(pid_t child_pid, int sockfd)
*
*	Configure the a given child's user namespace and then pause until the
*	process tree of the child exits.
*
*/
int handle_child_uid_map (pid_t child_pid, int sockfd) {
	int uid_map = 0;
	int has_userns = -1;
	if (read(sockfd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
		fprintf(stderr, "couldn't read from child!\n");
		return -1;
	}
	if (has_userns) {
		char path[PATH_MAX] = {0};
		for (char** file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
			if ((long unsigned int) snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file) > sizeof(path)) {
				fprintf(stderr, "snprintf size exceeded: %m\n");
				return -1;
			}
			fprintf(stderr, "writing %s...", path);
			if ((uid_map = open(path, O_WRONLY)) == -1) {
				fprintf(stderr, "failed to open: %m\n");
				return -1;
			}
			if(dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
				fprintf(stderr, "dprintf failed: %m\n");
				close(uid_map);
				return -1;
			}
			close(uid_map);
		}
	}
	if (write(sockfd, &(int) {0}, sizeof(int)) != sizeof(int)) {
		fprintf(stderr, "couldn't write: %m\n");
		return -1;
	}

	return 0;	
}

/*
*	int userns(struct child_config* conf)
*
*	Communicate with parent process over whether or not to set uid and gid mappings.
*	If so, setgroups, setresgid, and setresuid for the child. Assumes that every uid
*	has a corresponding gid, which may not be universal.
*
*/
int userns(struct child_config* conf) {
	fprintf(stderr, ">> trying to namespace a user...");
	int has_userns = !unshare(CLONE_NEWUSER);
	if (write(conf->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
		fprintf(stderr, "couldn't write: %m\n");
		return -1;
	}
	int result = 0;
	if (read(conf->fd, &result, sizeof(result)) != sizeof(result)) {
		fprintf(stderr, "couldn't read: %m\n");
		return -1;
	}
	if (result) return -1;
	if (has_userns) {
		fprintf(stderr, "done.\n");
	} else {
		fprintf(stderr, "possibly unsupported, continuing anyway.\n");
	}
	fprintf(stderr, ">> switching to uid %d / gid %d...", conf->uid, conf->uid);
	if (setgroups(1, &(gid_t) {conf->uid}) ||
		setresgid(conf->uid, conf->uid, conf->uid) ||
		setresuid(conf->uid, conf->uid, conf->uid)) {
			fprintf(stderr, "failed: %m\n");
			return -1;		
	}
	fprintf(stderr, "done.\n");
	return 0;
}

/*
*	int child(void* arg)
*
*	Perform setup, switch users & groups, and load target executable
*	for a given child.
*
*/
int child(void* arg) {
	struct child_config* conf = arg;
	if(sethostname(conf->hostname, strlen(conf->hostname))
		|| mounts(conf)			// setup user mount namespace
		|| userns(conf)			// setup user namespace
		|| drop_capabilities()	// drop capabilities
		|| syscalls()) {
			close(conf->fd);
			return -1;
	}
	if (close(conf->fd)) {
		fprintf(stderr, "closing child socket failed: %m\n");
		return -1;
	}
	if(execve(conf->argv[0], conf->argv, NULL)) {
		fprintf(stderr, "execve executable load failed: %m\n");
		return -1;
	}
	return 0;
}

/*
*	int generate_hostname(char* buf, size_t len)
*
*	Generates a child hostname of length 'len' based on set prefix & system time
*	and writes it to string buffer 'buf'
*
*/
int generate_hostname (char* buf, size_t len) {
	struct timespec now = {0};
	clock_gettime(CLOCK_MONOTONIC, &now);
	snprintf(buf, len, "dropcan_%ld\n", now.tv_nsec);
	return 0;
}


/**************************/
/*      main routine      */
/**************************/


int main (int argc, char* argv[]) {
	struct child_config conf = {0};
	int err = 0;
	int option = 0;
	int socks[2] = {0};
	pid_t child_pid = 0;
	int last_optind = 0;
	while ((option = getopt(argc, argv, "c:m:u"))) {
		switch (option) {
			case 'c':
				conf.argc = argc - last_optind - 1;
				conf.argv = &argv[argc - conf.argc];
				goto finish_options;
			case 'm':
				conf.mnt_dir = optarg;
				break;
			case 'u':
				if(sscanf(optarg, "%d", &conf.uid) != 1){
					fprintf(stderr, "invalid uid: %s\n", optarg);
					goto usage;
				}
				break;
			default:
				goto usage;
		}
		last_optind = optind;
	}
	
finish_options:
	if(!conf.argc)	goto usage;
	if(!conf.mnt_dir) goto usage;

	/*    linux version check    */
	fprintf(stderr, ">> validating Linux version...");
	struct utsname host = {0};
	if (uname(&host)) {
		fprintf(stderr, "validation failed: %m\n");
		goto cleanup;
	}
	int ver_major = -1;
	int ver_minor = -1;
	if (sscanf(host.release, "%u.%u.", &ver_major, &ver_minor) != 2) {
		fprintf(stderr, "invalid release format: %s\n", host.release);
		goto cleanup;
	}
	if (ver_major != KERNEL_VER_MAJOR || ver_minor != KERNEL_VER_MINOR) {
		fprintf(stderr, "incompatible kernel version: %s - expected %d.%d.x\n", 
						host.release, KERNEL_VER_MAJOR, KERNEL_VER_MINOR);
		goto cleanup;
	}
	if (strcmp("x86_64", host.machine)) {
		fprintf(stderr, "incompatible system architecture: %s", host.machine);
		goto cleanup;
	}
	fprintf(stderr, "Linux version %s on %s", host.release, host.machine);
	
	char hostname[256] = {0};
	if (generate_hostname(hostname, sizeof(hostname))) goto error;
	conf.hostname = hostname;
	/*****************************/


	/*    namespaces    */
	if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, socks)) {
		fprintf(stderr, "socket pairing failed: %m\n");
		goto error;
	}
	if (fcntl(socks[0], F_SETFD, FD_CLOEXEC)) {
		fprintf(stderr, "file descriptor configuration failed: %m\n");
		goto error;
	}
	conf.fd = socks[1];
	
	#define STACK_SIZE (1024*1024)
	char* stack = 0;
	if (!(stack = malloc(STACK_SIZE))) {
		fprintf(stderr, ">> stack allocation failed\n");
	}
	if (resources(%conf)) {
		err = 1;
		goto clear_resources;
	}
	int flags = CLONE_NEWNS
				| CLONE_NEWCGROUP
				| CLONE_NEWPID
				| CLONE_NEWIPC
				| CLONE_NEWNET
				| CLONE_NEWUTS;
	if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &conf)) == -1) {
		fprintf(stderr, ">> stack clone failed! %m\n");
		err = 1;
		goto clear_resources
	}
	close(socks[1]);
	socks[1] = 0;
	
	goto cleanup;
	
	/********************/

usage:
	fprintf(stderr, "usage: %s -u -1 -m . -c /bin/sh ~\n", argv[0]);
	
error:
	err = 1;
	
cleanup:
	if(socks[0]) close(socks[0]);
	if(socks[1]) close(socks[1]);
	
	return err;
}
