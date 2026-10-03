# CTF2 Open API Reference

Authentication: browser OAuth for interactive clients; PAT via `Authorization: Bearer <token>` or `X-CTF2-API-Key: <token>` for scripts. Never persist a PAT in the Skill directory.

User API base: `https://ctf2.dasctf.com/api/open/v1/user`.

OpenAPI 3.1 documents: [`user.json`](https://ctf2.dasctf.com/api/openapi/v1/user.json), [`user.yaml`](https://ctf2.dasctf.com/api/openapi/v1/user.yaml), [`admin.json`](https://ctf2.dasctf.com/api/openapi/v1/admin.json), and [`admin.yaml`](https://ctf2.dasctf.com/api/openapi/v1/admin.yaml).

Environment start responses expose safe `access_url`/`access_urls` fields when `access_ready` is true. Practice challenge file metadata exposes an authenticated `download_url`. PAT and MCP flag submissions use external credential rate limits and challenge attempt limits instead of browser CAPTCHA; the Cap proof-of-work `captcha_token` only applies to interactive web submissions and is not part of the Open API submit body.

## User endpoints

- `GET /api/open/v1/user/profile/` — operation `user_get_profile` — scope `profile:read` — Read current profile.
- `PUT /api/open/v1/user/profile/` — operation `user_put_profile` — scope `profile:write` — Update current profile username, avatar, bio, or invisible mode.
- `GET /api/open/v1/user/announcements/` — operation `user_get_announcements` — scope `profile:read` — List active announcements.
- `GET /api/open/v1/user/platform-update-logs/` — operation `user_get_platform_update_logs` — scope `platform:update:read` — List published platform update logs.
- `GET /api/open/v1/user/daily/` — operation `user_get_daily` — scope `daily:read` — List visible daily challenges.
- `GET /api/open/v1/user/practice/` — operation `user_get_practice` — scope `practice:read` — List visible public practice grounds.
- `GET /api/open/v1/user/practice/{id}/challenges/` — operation `user_get_practice_id_challenges` — scope `practice:read` — List visible challenges in a practice ground with the caller's solve state; filter by category, difficulty, or unsolved_only.
- `GET /api/open/v1/user/practice/{id}/challenges/{challengeId}/` — operation `user_get_practice_id_challenges_challengeid` — scope `practice:read` — Read an authorized practice challenge and current suite progress.
- `GET /api/open/v1/user/practice/{id}/challenges/{challengeId}/files/{fileId}/download/` — operation `user_get_practice_id_challenges_challengeid_files_fileid_download` — scope `practice:read` — Issue a signed attachment download URL that expires after 5 minutes and is bound to the caller.
- `POST /api/open/v1/user/practice/{id}/challenges/{challengeId}/submit/` — operation `user_post_practice_id_challenges_challengeid_submit` — scope `practice:submit` — Submit a confirmed practice flag; suites require a stable sub_flag_id from challenge details.
- `POST /api/open/v1/user/practice/{id}/challenges/{challengeId}/environment/start/` — operation `user_post_practice_id_challenges_challengeid_environment_start` — scope `environment:write` — Start or reuse a practice environment.
- `GET /api/open/v1/user/practice/{id}/challenges/{challengeId}/environment/` — operation `user_get_practice_id_challenges_challengeid_environment` — scope `environment:read` — Read the current practice environment status, access URLs, and remaining time.
- `POST /api/open/v1/user/practice/{id}/challenges/{challengeId}/environment/extend/` — operation `user_post_practice_id_challenges_challengeid_environment_extend` — scope `environment:write` — Extend the running practice environment with the same renewal rules as the web console.
- `DELETE /api/open/v1/user/practice/{id}/challenges/{challengeId}/environment/` — operation `user_delete_practice_id_challenges_challengeid_environment` — scope `environment:write` — Destroy the current practice environment.
- `GET /api/open/v1/user/agent/me/` — operation `user_get_agent_me` — scope `agent:read` — Read the calling Agent's profile, results, quotas, allowed tools, and rules (Agent credentials only).
- `GET /api/open/v1/user/agent/next-challenges/` — operation `user_get_agent_next_challenges` — scope `agent:read` — Recommend unsolved public practice challenges, easiest and most-solved first (Agent credentials only).
- `POST /api/open/v1/user/agent/notes/` — operation `user_post_agent_notes` — scope `agent:trace` — Record a plan, finding, or result note for the Agent's solution replay (Agent credentials only).
- `GET /api/open/v1/user/private-practice/` — operation `user_get_private_practice` — scope `practice:read` — List private practice grounds available to current user.
- `GET /api/open/v1/user/private-practice/submissions/` — operation `user_get_private_practice_submissions` — scope `submission:read` — List private practice submissions for current user.
- `GET /api/open/v1/user/competitions/` — operation `user_get_competitions` — scope `competition:read` — List visible competitions.
- `GET /api/open/v1/user/competitions/{id}/status/` — operation `user_get_competitions_id_status` — scope `competition:read` — Read competition status and stages.
- `GET /api/open/v1/user/competitions/{id}/teams/` — operation `user_get_competitions_id_teams` — scope `competition:read` — List competition teams.
- `GET /api/open/v1/user/competitions/{id}/stages/` — operation `user_get_competitions_id_stages` — scope `competition:read` — List competition stages.
- `GET /api/open/v1/user/stages/{stageId}/` — operation `user_get_stages_stageid` — scope `competition:read` — Read a stage.
- `GET /api/open/v1/user/stages/{stageId}/challenges/` — operation `user_get_stages_stageid_challenges` — scope `competition:read` — List visible stage challenges.
- `GET /api/open/v1/user/stages/{stageId}/submissions/` — operation `user_get_stages_stageid_submissions` — scope `submission:read` — List current user submissions in a stage.
- `GET /api/open/v1/user/stages/{stageId}/tickets/` — operation `user_get_stages_stageid_tickets` — scope `ticket:read` — List current user tickets in a stage.
- `GET /api/open/v1/user/tickets/` — operation `user_get_tickets` — scope `ticket:read` — List current user global tickets.
- `POST /api/open/v1/user/tickets/` — operation `user_post_tickets` — scope `ticket:write` — Create a global support ticket.
- `POST /api/open/v1/user/tickets/{id}/replies/` — operation `user_post_tickets_id_replies` — scope `ticket:write` — Reply to a global support ticket.
- `POST /api/open/v1/user/tickets/{id}/transition/` — operation `user_post_tickets_id_transition` — scope `ticket:write` — Move own support ticket through allowed user-side statuses.
- `GET /api/open/v1/user/submissions/` — operation `user_get_submissions` — scope `submission:read` — List current user submissions.
- `GET /api/open/v1/user/teams/` — operation `user_get_teams` — scope `team:read` — List teams.
- `GET /api/open/v1/user/team/my/` — operation `user_get_team_my` — scope `team:read` — Read current user team.
- `GET /api/open/v1/user/teams/{id}/` — operation `user_get_teams_id` — scope `team:read` — Read a team.
- `GET /api/open/v1/user/learning/events/` — operation `user_get_learning_events` — scope `learning:read` — List current user learning events.
- `GET /api/open/v1/user/learning/recommendations/` — operation `user_get_learning_recommendations` — scope `learning:read` — Read learning recommendations.
- `GET /api/open/v1/user/points/` — operation `user_get_points` — scope `learning:read` — List current user point balances.
- `GET /api/open/v1/user/points/transactions/` — operation `user_get_points_transactions` — scope `learning:read` — List current user point transactions.
- `GET /api/open/v1/user/point-shop/products/` — operation `user_get_point_shop_products` — scope `learning:read` — List active point shop products.
- `GET /api/open/v1/user/point-shop/orders/` — operation `user_get_point_shop_orders` — scope `learning:read` — List current user point shop orders.
- `GET /api/open/v1/user/community/feeds/` — operation `user_get_community_feeds` — scope `community:read` — List visible community feeds.
- `GET /api/open/v1/user/community/topics/` — operation `user_get_community_topics` — scope `community:read` — List community topics.
- `GET /api/open/v1/user/community/discussions/` — operation `user_get_community_discussions` — scope `community:read` — List visible community discussions.
- `GET /api/open/v1/user/courses/` — operation `user_get_courses` — scope `learning:read` — List published courses.
- `GET /api/open/v1/user/classes/my/` — operation `user_get_classes_my` — scope `learning:read` — List current user class enrollments.
- `GET /api/open/v1/user/writeups/` — operation `user_get_writeups` — scope `writeup:read` — List public approved writeups.
- `GET /api/open/v1/user/writeups/my/` — operation `user_get_writeups_my` — scope `writeup:read` — List current user writeups.

Admin API base: `https://ctf2.dasctf.com/api/open/v1/admin`. Use only admin-scoped keys.

## Admin endpoints

- `GET /api/open/v1/admin/users/` — operation `admin_get_users` — scope `admin:user:read` — List users for integrations.
- `GET /api/open/v1/admin/user-groups/` — operation `admin_get_user_groups` — scope `admin:user:read` — List user groups.
- `GET /api/open/v1/admin/teams/` — operation `admin_get_teams` — scope `admin:user:read` — List teams.
- `GET /api/open/v1/admin/user-points/` — operation `admin_get_user_points` — scope `admin:user:read` — List user point balances.
- `GET /api/open/v1/admin/point-transactions/` — operation `admin_get_point_transactions` — scope `admin:user:read` — List point transactions.
- `GET /api/open/v1/admin/competitions/` — operation `admin_get_competitions` — scope `admin:competition:read` — List competitions.
- `GET /api/open/v1/admin/stages/` — operation `admin_get_stages` — scope `admin:competition:read` — List competition stages.
- `GET /api/open/v1/admin/competition-calendar/` — operation `admin_get_competition_calendar` — scope `admin:competition:read` — List competition calendar entries.
- `GET /api/open/v1/admin/challenges/` — operation `admin_get_challenges` — scope `admin:challenge:read` — List competition challenges.
- `GET /api/open/v1/admin/practice/` — operation `admin_get_practice` — scope `admin:practice:read` — List practice grounds.
- `GET /api/open/v1/admin/private-practice/` — operation `admin_get_private_practice` — scope `admin:practice:read` — List private practice grounds.
- `GET /api/open/v1/admin/problem-templates/` — operation `admin_get_problem_templates` — scope `admin:challenge:read` — List question bank problem templates.
- `GET /api/open/v1/admin/problem-templates/{id}/` — operation `admin_get_problem_templates_id` — scope `admin:challenge:read` — Read one question bank problem template with files, tags, sets, and flags.
- `GET /api/open/v1/admin/problem-tags/` — operation `admin_get_problem_tags` — scope `admin:challenge:read` — List active question bank tags.
- `GET /api/open/v1/admin/problem-sets/` — operation `admin_get_problem_sets` — scope `admin:challenge:read` — List active question bank sets.
- `GET /api/open/v1/admin/announcements/` — operation `admin_get_announcements` — scope `admin:content:read` — List announcements.
- `GET /api/open/v1/admin/courses/` — operation `admin_get_courses` — scope `admin:content:read` — List courses.
- `GET /api/open/v1/admin/classes/` — operation `admin_get_classes` — scope `admin:class:read` — List classes.
- `GET /api/open/v1/admin/certificates/` — operation `admin_get_certificates` — scope `admin:content:read` — List certificates.
- `GET /api/open/v1/admin/content-blocks/` — operation `admin_get_content_blocks` — scope `admin:content:read` — List course content blocks.
- `GET /api/open/v1/admin/content-block-groups/` — operation `admin_get_content_block_groups` — scope `admin:content:read` — List content block groups.
- `GET /api/open/v1/admin/writeups/` — operation `admin_get_writeups` — scope `admin:content:read` — List writeups.
- `GET /api/open/v1/admin/banners/` — operation `admin_get_banners` — scope `admin:content:read` — List homepage banners.
- `GET /api/open/v1/admin/news/` — operation `admin_get_news` — scope `admin:content:read` — List news.
- `GET /api/open/v1/admin/community/feeds/` — operation `admin_get_community_feeds` — scope `admin:content:read` — List community feeds.
- `GET /api/open/v1/admin/community/topics/` — operation `admin_get_community_topics` — scope `admin:content:read` — List community topics.
- `GET /api/open/v1/admin/community/reports/` — operation `admin_get_community_reports` — scope `admin:ops:read` — List community reports.
- `GET /api/open/v1/admin/settings/` — operation `admin_get_settings` — scope `admin:system:read` — List system settings.
- `GET /api/open/v1/admin/point-rules/` — operation `admin_get_point_rules` — scope `admin:system:read` — List point rules.
- `GET /api/open/v1/admin/point-event-types/` — operation `admin_get_point_event_types` — scope `admin:system:read` — List point event types.
- `GET /api/open/v1/admin/point-shop/categories/` — operation `admin_get_point_shop_categories` — scope `admin:content:read` — List point shop categories.
- `GET /api/open/v1/admin/point-shop/products/` — operation `admin_get_point_shop_products` — scope `admin:content:read` — List point shop products.
- `GET /api/open/v1/admin/point-shop/orders/` — operation `admin_get_point_shop_orders` — scope `admin:ops:read` — List point shop orders.
- `GET /api/open/v1/admin/ticket-categories/` — operation `admin_get_ticket_categories` — scope `admin:ops:read` — List ticket categories.
- `GET /api/open/v1/admin/tasks/` — operation `admin_get_tasks` — scope `admin:ops:read` — List task executions.
- `GET /api/open/v1/admin/queues/` — operation `admin_get_queues` — scope `admin:ops:read` — List queued tasks.
- `GET /api/open/v1/admin/logs/access/` — operation `admin_get_logs_access` — scope `admin:ops:read` — List access logs.
- `GET /api/open/v1/admin/logs/audit/` — operation `admin_get_logs_audit` — scope `admin:ops:read` — List system audit logs.
- `GET /api/open/v1/admin/logs/errors/` — operation `admin_get_logs_errors` — scope `admin:ops:read` — List error logs.
- `GET /api/open/v1/admin/files/` — operation `admin_get_files` — scope `admin:ops:read` — List files.
- `GET /api/open/v1/admin/docker-images/` — operation `admin_get_docker_images` — scope `admin:ops:read` — List Docker images.
- `GET /api/open/v1/admin/targets/` — operation `admin_get_targets` — scope `admin:ops:read` — List targets.
- `GET /api/open/v1/admin/k8s-clusters/` — operation `admin_get_k8s_clusters` — scope `admin:ops:read` — List Kubernetes clusters.
- `GET /api/open/v1/admin/sos/` — operation `admin_get_sos` — scope `admin:ops:read` — List SOS reports.
- `GET /api/open/v1/admin/audit/open-api/` — operation `admin_get_audit_open_api` — scope `admin:ops:read` — List Open API call audit logs.
- `POST /api/open/v1/admin/news/` — operation `admin_post_news` — scope `admin:content:write` — Create a news item through the reviewed admin write allowlist.
- `PUT /api/open/v1/admin/news/{id}/` — operation `admin_put_news_id` — scope `admin:content:write` — Update a news item through the reviewed admin write allowlist.
- `DELETE /api/open/v1/admin/news/{id}/` — operation `admin_delete_news_id` — scope `admin:content:write` — Delete a news item through the reviewed admin write allowlist.

## Scope catalog

User scopes: `agent:read`, `agent:trace`, `community:read`, `competition:read`, `daily:read`, `environment:read`, `environment:write`, `learning:read`, `platform:update:read`, `practice:read`, `practice:submit`, `profile:read`, `profile:write`, `submission:read`, `team:read`, `ticket:read`, `ticket:write`, `writeup:read`.

Admin scopes: `admin:challenge:read`, `admin:class:read`, `admin:competition:read`, `admin:content:read`, `admin:content:write`, `admin:ops:read`, `admin:practice:read`, `admin:system:read`, `admin:user:read`.
