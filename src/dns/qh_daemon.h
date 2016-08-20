#ifndef QH_DAEMON_H
#define QH_DAEMON_H
void pkt_divert_start(void (*thread_switch_wrapper)(void (*)(void)));
void qh_daemon_signal(int);
#endif
