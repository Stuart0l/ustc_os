#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

bool is_pipe(char *cmd) {
	int i;
	for (i = 0; cmd[i]; i++)
		if (cmd[i] == '|')
			return true;
	return false;
}

void exec_bin(char *executable, char *argv[]) {
	pid_t pid = fork();

	if (pid < 0) {
		printf("fork failed\n");
	} else if (pid == 0) {  // child
		char path_bin[256] = "/bin/", path_usr_bin[256] = "/usr/bin/";
		strcat(path_bin, executable);
		strcat(path_usr_bin, executable);

		if (access(path_bin, X_OK) == 0) {
			execv(path_bin, argv);
		} else if (access(path_usr_bin, X_OK) == 0) {
			execv(path_usr_bin, argv);
		} else {
			printf("%s: command not found\n", executable);
			exit(0);
		}
	} else {  // parent
		waitpid(pid, NULL, 0);
	}
}

void exec_cmd(char *cmd) {
	char *command, *arg;
	char *argv[256];
	int i = 0;

	while ((command = strsep(&cmd, " ")) != NULL){
		if (strlen(command) > 0)
			break;
	}

	if (command == NULL)
		return;

	if (strcmp(command, "exit") == 0)
		exit(0);
	else {
		// printf("ex:%s\n", command);
		argv[i++] = command;

		while ((arg = strsep(&cmd, " ")) != NULL) {
			if (strlen(arg) > 0){
				// printf("%s\n", arg);
				argv[i++] = arg;
			}
		}

		argv[i] = NULL;

		if (strcmp(command, "cd") == 0) { // cd
			if (i < 2) {
				printf("no enough args for cd\n");
				return;
			}

			if (chdir(argv[1]) != 0) {
				printf("dir %s does not exit\n", argv[1]);
				return;
			}
		} else {
			exec_bin(command, argv);
		}
	}	
}

int main() {
	char cmdline[256];
	char seps[] = ";";

	while(1) {
		printf("OSLab2->");

		if (fgets(cmdline, 256, stdin) != NULL) {
			char* cmd = (char*)cmdline;
			char* subcmd;

			cmd = strsep(&cmd, "\n");
			// printf("cmd: %s len:%d\n", cmd, strlen(cmd));

			while ((subcmd = strsep(&cmd, ";")) != NULL){
				// printf("subcmd: %s len:%d\n", subcmd, strlen(subcmd));
				if (strlen(subcmd) == 0)
					continue;

				if (is_pipe(subcmd)) {
					char *cmd1, *cmd2;
					cmd1 = strsep(&subcmd, "|");
					cmd2 = subcmd;

					// printf("%s, %s\n", cmd1, cmd2);

					FILE *p_read = popen(cmd1, "r");
					FILE *p_write = popen(cmd2, "w");

					char buff[1024] = {0};

					while (fgets(buff, 1024, p_read) != NULL) {
						fputs(buff, p_write);
					}

					pclose(p_read);
					pclose(p_write);
				}
				else {
					exec_cmd(subcmd);
				}
			}
		}
	}
}