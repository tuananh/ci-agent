#pragma once

struct ci_agent_broadcaster;

extern int ci_agent_broadcaster_init(struct ci_agent_broadcaster **out,
				       const char *listen_path);

extern void ci_agent_broadcaster_fini(struct ci_agent_broadcaster *broadcaster);

extern void ci_agent_broadcaster_send(struct ci_agent_broadcaster *broadcaster,
					const char *buf, ...);

extern int ci_agent_broadcaster_fd(const struct ci_agent_broadcaster *broadcaster);

extern int ci_agent_broadcaster_accept(struct ci_agent_broadcaster *broadcaster);
