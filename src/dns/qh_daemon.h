#ifndef QH_DAEMON_H
#define QH_DAEMON_H

/*
Play modes for the verdict hooks.
*/
typedef enum {LEARNING,	/*Used for training or learning current profiles.*/
			PERMISSIVE,	/*Aggressively log abnormalities, but let everything through.*/
			STRICT		/*Enforce the specified policy over the monitored traffic.*/
} ENFORCEMENT_MODE;

void pkt_divert_start(ENFORCEMENT_MODE mode, void (*thread_switch_wrapper)(void (*)(void)));
void qh_daemon_signal(int);
void set_log_level(int level);

#endif

