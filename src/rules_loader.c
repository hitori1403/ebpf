#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "types.h"
#include "constants.h"
#include "main.skel.h"

#include "tpm2_utils.c"
#include "fnv1a.c"

struct proc_info {
	u32 uid;
	u32 pid;
	u32 ppid;
	char cwd[PATH_MAX];
	char path[PATH_MAX];
	u8 perm;
	u8 log;
};

enum parser_state {
	STATE_START,
	STATE_STREAM,
	STATE_DOCUMENT,
	STATE_SECTION,

	STATE_RULE,
	STATE_RULE_LIST,
	STATE_RULE_VALUE,

	STATE_FILE,

	STATE_PROCESS_LIST,
	STATE_PROCESS_VALUES,
	STATE_PROCESS,

	STATE_PROCESS_ATTRIBUTES,
	STATE_PROCESS_ATTRIBUTE_KEY,
	STATE_PROCESS_USER,
	STATE_PROCESS_PID,
	STATE_PROCESS_PPID,
	STATE_PROCESS_PERMISSION,
	STATE_PROCESS_CWD,
	STATE_PROCESS_LOG,

	STATE_LOG_LIST,

	STATE_STOP /* end state */
};

enum log_type_value { OPEN = 1, READ = 2, WRITE = 4 };

struct log_entry {
	char *log_type;
	struct log_entry *next;
};

struct process_entry {
	char *path;
	char *user;
	char *perm;
	char *cwd;
	int pid;
	int ppid;
	struct process_entry *next;
	struct log_entry *last_log;
	struct log_entry *log_list;
};

struct file_entry {
	char *path;
	struct file_entry *next;
	struct process_entry *last_process;
	struct process_entry *process_list;
};

struct yaml_parser_state {
	enum parser_state state;
	struct file_entry *last_file;
	struct file_entry *file_list;
};

int consume_event(struct yaml_parser_state *s, yaml_event_t *event)
{
	char *value;

	switch (s->state) {
	case STATE_START:
		switch (event->type) {
		case YAML_STREAM_START_EVENT:
			s->state = STATE_STREAM;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_STREAM:
		switch (event->type) {
		case YAML_DOCUMENT_START_EVENT:
			s->state = STATE_DOCUMENT;
			break;
		case YAML_STREAM_END_EVENT:
			s->state = STATE_STOP;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_DOCUMENT:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_RULE;
			break;
		case YAML_DOCUMENT_END_EVENT:
			s->state = STATE_STREAM;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			if (!strcmp(value, "rules")) {
				s->state = STATE_RULE_LIST;
			} else {
				fprintf(stderr, "Unexpected scalar: %s\n", value);
				return EXIT_FAILURE;
			}
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_DOCUMENT;
			break;
		case YAML_DOCUMENT_END_EVENT:
			s->state = STATE_STREAM;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE_LIST:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_RULE_VALUE;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_RULE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE_VALUE:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_FILE;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_RULE_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_RULE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_FILE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct file_entry *f = calloc(1, sizeof(struct file_entry));
			f->path = strdup(value);
			if (s->file_list == NULL)
				s->file_list = f;
			else
				s->last_file->next = f;
			s->last_file = f;
			s->state = STATE_PROCESS_LIST;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_RULE_VALUE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_LIST:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_PROCESS_VALUES;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_FILE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_VALUES:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_PROCESS;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_FILE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct process_entry *p = calloc(1, sizeof(struct process_entry));
			p->path = strdup(value);
			if (s->last_file->process_list == NULL)
				s->last_file->process_list = p;
			else
				s->last_file->last_process->next = p;
			s->last_file->last_process = p;
			s->state = STATE_PROCESS_ATTRIBUTES;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS_VALUES;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_ATTRIBUTES:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_ATTRIBUTE_KEY:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			if (!strcmp(value, "user"))
				s->state = STATE_PROCESS_USER;
			else if (!strcmp(value, "pid"))
				s->state = STATE_PROCESS_PID;
			else if (!strcmp(value, "ppid"))
				s->state = STATE_PROCESS_PPID;
			else if (!strcmp(value, "perm"))
				s->state = STATE_PROCESS_PERMISSION;
			else if (!strcmp(value, "cwd"))
				s->state = STATE_PROCESS_CWD;
			else if (!strcmp(value, "log"))
				s->state = STATE_PROCESS_LOG;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_USER:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->user = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->pid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PPID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->ppid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PERMISSION:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->perm = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_CWD:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->cwd = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_LOG:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_LOG_LIST;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_LOG_LIST:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct log_entry *l = calloc(1, sizeof(struct log_entry));
			l->log_type = strdup(value);
			if (s->last_file->last_process->log_list == NULL)
				s->last_file->last_process->log_list = l;
			else
				s->last_file->last_process->last_log->next = l;
			s->last_file->last_process->last_log = l;
			s->state = STATE_LOG_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_STOP:
		return 0;

	default:
		break;
	}

	return 0;
}

/* void clean(struct yaml_parser_state *state)
{
	for (struct file_entry *f = state->file_list; f;) {
		for (struct process_entry *p = f->process_list; p;) {
			free(p->path);
			free(p->user);
			free(p->cwd);
			free(p->perm);
			for (struct log_entry *l = p->log_list; l;) {
				struct log_entry *tmp = l->next;
				free(l->log_type);
				free(l);
				l = tmp;
			}
			struct process_entry *tmp = p->next;
			free(p);
			p = tmp;
		}
		struct file_entry *tmp = f->next;
		free(f);
		f = tmp;
	}
} */

int perm_to_num(const char *perm)
{
	if (!perm)
		return 0;

	int num = 0;
	for (const char *c = perm; *c; ++c) {
		switch (*c) {
		case 'r':
			num |= 4;
			break;
		case 'w':
			num |= 2;
			break;
		case 'x':
			num |= 1;
			break;
		default:
			fprintf(stderr, "Unknown permission: %s", perm);
			exit(EXIT_FAILURE);
		}
	}
	return num;
}

struct key_info {
	u64 hash;
	char key[KEY_LENGTH_MAX];
	char nonce[NONCE_LENGTH_MAX];
};

int cmp_key_info(const void *a, const void *b)
{
	return ((struct key_info *)a)->hash < ((struct key_info *)b)->hash ? -1 : 1;
}

unsigned int read_len(int fd, unsigned int limit)
{
	unsigned int len;
	int sz = read(fd, &len, 4);

	if (sz == 0)
		return -1;

	if (sz != 4) {
		fprintf(stderr, "Invalid key\n");
		exit(1);
	}

	if (len > limit) {
		fprintf(stderr, "Length must be no more than 4096\n");
		exit(1);
	}

	return len;
}

bool read_buf(int fd, char *buf, unsigned int limit)
{
	unsigned int len = read_len(fd, limit);
	if (len == -1)
		return false;
	unsigned int sz = read(fd, buf, len);
	if (sz < len)
		return false;
	buf[sz] = 0;
	return true;
}

int load_keys(struct key_info *key_info_arr, const char *file_path)
{
	int fd = open(file_path, O_RDONLY), cnt = 0;
	if (fd == -1) {
		perror("Failed to open keys file");
		exit(-1);
	}

	while (1) {
		char filepath[4100];
		char key[KEY_LENGTH_MAX];
		char nonce[NONCE_LENGTH_MAX];
		if (!read_buf(fd, filepath, 4096))
			break;

		if (!read_buf(fd, key, 32))
			break;

		if (!read_buf(fd, nonce, 12))
			break;

		key_info_arr[cnt].hash = fnv1a((u8 *)filepath, strlen(filepath));
		memcpy(key_info_arr[cnt].key, key, KEY_LENGTH_MAX);
		memcpy(key_info_arr[cnt].nonce, strdup(nonce), NONCE_LENGTH_MAX);
		++cnt;
	}

	qsort(key_info_arr, cnt, sizeof(struct key_info), cmp_key_info);

	if (close(fd) < 0) {
		perror("Error: ");
		exit(-1);
	}

	return cnt;
}

int binsearch(struct key_info *key_info_arr, unsigned int cnt, u64 path_hash)
{
	int l = 0, r = cnt - 1, ret = -1;
	while (l <= r) {
		int mid = (l + r) >> 1;
		if (path_hash == key_info_arr[mid].hash)
			ret = mid;
		if (path_hash > key_info_arr[mid].hash)
			l = mid + 1;
		else
			r = mid - 1;
	}
	return ret;
}

void gen_bytes(char *buf, unsigned int len)
{
	if (len < 1 || len > 48) {
		printf("Length must be in range [1, 48]");
		exit(1);
	}

	char cmd[20];
	sprintf(cmd, "tpm2_getrandom %d", len);
	FILE *fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("popen");
		exit(1);
	}

	fgets(buf, len + 1, fp);
	buf[len] = 0;
	pclose(fp);
}

void write_key(struct key_info *saved, FILE *file, char *path, unsigned int key_len,
	       unsigned int nonce_len)
{
	gen_bytes(saved->key, key_len);
	gen_bytes(saved->nonce, nonce_len);
	unsigned int path_len = strlen(path);
	fwrite(&path_len, sizeof(char), sizeof(unsigned int), file);
	fwrite(path, sizeof(char), path_len, file);
	fwrite(&key_len, sizeof(char), sizeof(unsigned int), file);
	fwrite(saved->key, sizeof(char), key_len, file);
	fwrite(&nonce_len, sizeof(char), sizeof(unsigned int), file);
	fwrite(saved->nonce, sizeof(char), nonce_len, file);
	// exit(EXIT_FAILURE);
}

int load_rules_to_bpf_map(struct main_bpf *skel, const char *file_path)
{
	tpm2_decrypt();

	if (!access(KEY_FILE, F_OK) == 0)
		exit(EXIT_FAILURE);

	struct key_info *key_info_arr = calloc(1024, sizeof(struct key_info));
	unsigned int cnt_key = load_keys(key_info_arr, KEY_FILE);

	FILE *key_file = fopen(KEY_FILE, "a+");
	if (!key_file) {
		perror("Faild to open keys file");
		exit(EXIT_FAILURE);
	}

	FILE *input = fopen(file_path, "rb");
	if (!input) {
		perror("Failed to open rules file");
		exit(EXIT_FAILURE);
	}

	int exit_code = 0;

	yaml_parser_t parser;
	yaml_event_t event;
	struct yaml_parser_state *state = malloc(sizeof(struct yaml_parser_state));

	memset(state, 0, sizeof(struct yaml_parser_state));

	state->state = STATE_START;

	if (!yaml_parser_initialize(&parser)) {
		perror("Could not initialize the parser object");
		exit(EXIT_FAILURE);
	}

	yaml_parser_set_input_file(&parser, input);

	do {
		if (!yaml_parser_parse(&parser, &event)) {
			perror(parser.problem);
			exit(EXIT_FAILURE);
		}

		if (consume_event(state, &event)) {
			fprintf(stderr, "consume_event error\n");
			exit_code = EXIT_FAILURE;
			goto cleanup;
		}

	} while (state->state != STATE_STOP);

	// TODO: vaidate value
	struct key_info *new_key = (struct key_info *)calloc(1, sizeof(struct key_info));
	for (struct file_entry *f = state->file_list; f; f = f->next) {
		struct proc_info proc[MAX_PROCESSES_PER_FILE];
		int i = 0;
		for (struct process_entry *p = f->process_list; p; p = p->next) {
			if (p->path)
				strcpy(proc[i].path, p->path);

			if (p->cwd)
				strcpy(proc[i].cwd, p->cwd);

			if (p->pid)
				proc[i].pid = p->pid;

			if (p->ppid)
				proc[i].ppid = p->ppid;

			if (p->perm)
				proc[i].perm = perm_to_num(p->perm);

			if (p->user) {
				struct passwd *pw;
				if ((pw = getpwnam(p->user)) == NULL) {
					fprintf(stderr, "Username not found: %s\n", p->user);
					exit(EXIT_FAILURE);
				}
				proc[i].uid = pw->pw_uid;
			}

			proc[i].log = 0;
			for (struct log_entry *l = p->log_list; l; l = l->next) {
				if (!strcmp(l->log_type, "read"))
					proc[i].log |= READ;
				else if (!strcmp(l->log_type, "write"))
					proc[i].log |= WRITE;
				else if (!strcmp(l->log_type, "open"))
					proc[i].log |= OPEN;
				else {
					fprintf(stderr, "Unknown log type: %s", l->log_type);
					exit(EXIT_FAILURE);
				}
			}

			++i;
		}

		if (!f->path) {
			fprintf(stderr, "File path not found");
			exit(EXIT_FAILURE);
		}

		// TODO: using u128 for improved hash collision resistance
		u64 path_hash = fnv1a((u8 *)f->path, strlen(f->path));
		int search = binsearch(key_info_arr, cnt_key, path_hash);

		if (search == -1) {
			write_key(new_key, key_file, f->path, 32, 12);
		} else {
			memcpy(new_key->key, key_info_arr[search].key, KEY_LENGTH_MAX);
			memcpy(new_key->nonce, key_info_arr[search].nonce, NONCE_LENGTH_MAX);
		}
		bpf_map__update_elem(skel->maps.map_path_rules, &path_hash, sizeof(path_hash),
				     &proc, sizeof(proc), BPF_ANY);

		bpf_map__update_elem(skel->maps.map_keys, &path_hash, sizeof(path_hash), new_key,
				     sizeof(struct key_info), BPF_ANY);
	}

cleanup:
	fclose(key_file);
	fclose(input);
	tpm2_gen_iv();
	tpm2_encrypt();
	system("shred keys");
	system("rm keys");
	free(new_key);
	yaml_parser_delete(&parser);
	free(state);
	if (exit_code)
		exit(exit_code);
	return exit_code;
}
