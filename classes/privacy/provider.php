<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Privacy Subsystem implementation for mod_jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\privacy;

use core_privacy\local\metadata\collection;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\contextlist;
use core_privacy\local\request\userlist;
use core_privacy\local\request\writer;

/**
 * Privacy Subsystem implementation for mod_jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class provider implements
    \core_privacy\local\metadata\provider,
    \core_privacy\local\request\core_userlist_provider,
    \core_privacy\local\request\plugin\provider {
    /**
     * Returns meta data about this system.
     *
     * @param collection $collection The initialised collection to add items to.
     * @return collection A listing of user data stored through this system.
     */
    public static function get_metadata(collection $collection): collection {
        // Data sent to the Jitsi Meet server (identity inside the conference).
        $collection->add_external_location_link('jitsi', [
            'username' => 'privacy:metadata:jitsi:username',
            'avatar'   => 'privacy:metadata:jitsi:avatar',
            'email'    => 'privacy:metadata:jitsi:email',
        ], 'privacy:metadata:jitsi');

        // Recording content sent to Google Vertex AI for AI feature generation.
        $collection->add_external_location_link('vertexai', [
            'recording' => 'privacy:metadata:vertexai:recording',
        ], 'privacy:metadata:vertexai');

        // AI-generated content and recording creator stored in jitsi_source_record.
        $collection->add_database_table('jitsi_source_record', [
            'userid'           => 'privacy:metadata:jitsi_source_record:userid',
            'ai_summary'       => 'privacy:metadata:jitsi_source_record:ai_summary',
            'ai_transcription' => 'privacy:metadata:jitsi_source_record:ai_transcription',
            'ai_quiz_id'       => 'privacy:metadata:jitsi_source_record:ai_quiz_id',
        ], 'privacy:metadata:jitsi_source_record');

        // Anonymous usage telemetry sent to the mod_jitsi Account portal.
        $collection->add_external_location_link('mod_jitsi_portal', [
            'site_hash'      => 'privacy:metadata:portal:site_hash',
            'plugin_version' => 'privacy:metadata:portal:plugin_version',
            'moodle_branch'  => 'privacy:metadata:portal:moodle_branch',
            'server_type'    => 'privacy:metadata:portal:server_type',
            'activity_count' => 'privacy:metadata:portal:activity_count',
            'features'       => 'privacy:metadata:portal:features',
        ], 'privacy:metadata:portal');

        // Web Push subscriptions for private session notifications.
        $collection->add_database_table('jitsi_push_subscriptions', [
            'userid'    => 'privacy:metadata:jitsi_push_subscriptions:userid',
            'endpoint'  => 'privacy:metadata:jitsi_push_subscriptions:endpoint',
            'authkey'   => 'privacy:metadata:jitsi_push_subscriptions:authkey',
            'p256dhkey' => 'privacy:metadata:jitsi_push_subscriptions:p256dhkey',
        ], 'privacy:metadata:jitsi_push_subscriptions');

        // Pre-computed daily usage aggregates per user per activity.
        $collection->add_database_table('jitsi_usage_daily', [
            'userid'   => 'privacy:metadata:jitsi_usage_daily:userid',
            'sessions' => 'privacy:metadata:jitsi_usage_daily:sessions',
            'minutes'  => 'privacy:metadata:jitsi_usage_daily:minutes',
            'times'    => 'privacy:metadata:jitsi_usage_daily:times',
        ], 'privacy:metadata:jitsi_usage_daily');

        // Watched video segments per user per GCS recording.
        $collection->add_database_table('jitsi_recording_segments', [
            'userid'     => 'privacy:metadata:jitsi_recording_segments:userid',
            'segments'   => 'privacy:metadata:jitsi_recording_segments:segments',
            'playcounts' => 'privacy:metadata:jitsi_recording_segments:playcounts',
        ], 'privacy:metadata:jitsi_recording_segments');

        // Tutoring availability schedule for private sessions.
        $collection->add_database_table('jitsi_tutoring_schedule', [
            'userid'    => 'privacy:metadata:jitsi_tutoring_schedule:userid',
            'weekday'   => 'privacy:metadata:jitsi_tutoring_schedule:weekday',
            'timestart' => 'privacy:metadata:jitsi_tutoring_schedule:timestart',
            'timeend'   => 'privacy:metadata:jitsi_tutoring_schedule:timeend',
        ], 'privacy:metadata:jitsi_tutoring_schedule');

        // Real-time presence of participants in jitsi sessions.
        $collection->add_database_table('jitsi_presence', [
            'userid'    => 'privacy:metadata:jitsi_presence:userid',
            'guestname' => 'privacy:metadata:jitsi_presence:guestname',
        ], 'privacy:metadata:jitsi_presence');

        return $collection;
    }

    /**
     * Get the list of contexts that contain user information for the specified user.
     *
     * @param int $userid The user to search.
     * @return contextlist The list of contexts used in this plugin.
     */
    public static function get_contexts_for_userid(int $userid): contextlist {
        global $DB;

        $contextlist = new contextlist();

        // Table jitsi_usage_daily: CONTEXT_MODULE via cmid.
        $contextlist->add_from_sql(
            'SELECT ctx.id
               FROM {context} ctx
               JOIN {course_modules} cm ON cm.id = ctx.instanceid AND ctx.contextlevel = :ctxmodule
               JOIN {jitsi_usage_daily} ud ON ud.cmid = cm.id
              WHERE ud.userid = :userid',
            ['ctxmodule' => CONTEXT_MODULE, 'userid' => $userid]
        );

        // Table jitsi_recording_segments: CONTEXT_MODULE via cmid.
        $contextlist->add_from_sql(
            'SELECT ctx.id
               FROM {context} ctx
               JOIN {course_modules} cm ON cm.id = ctx.instanceid AND ctx.contextlevel = :ctxmodule
               JOIN {jitsi_recording_segments} rs ON rs.cmid = cm.id
              WHERE rs.userid = :userid',
            ['ctxmodule' => CONTEXT_MODULE, 'userid' => $userid]
        );

        // Table jitsi_presence: CONTEXT_MODULE via jitsi instance id.
        $contextlist->add_from_sql(
            'SELECT ctx.id
               FROM {context} ctx
               JOIN {course_modules} cm ON cm.instance = ctx.instanceid AND ctx.contextlevel = :ctxmodule
               JOIN {jitsi_presence} jp ON jp.jitsiid = cm.instance
              WHERE jp.userid = :userid AND jp.userid != 0',
            ['ctxmodule' => CONTEXT_MODULE, 'userid' => $userid]
        );

        // Table jitsi_source_record: CONTEXT_MODULE via jitsi_record join.
        $contextlist->add_from_sql(
            'SELECT ctx.id
               FROM {context} ctx
               JOIN {course_modules} cm ON cm.instance = ctx.instanceid AND ctx.contextlevel = :ctxmodule
               JOIN {jitsi_record} jr ON jr.jitsi = cm.instance
               JOIN {jitsi_source_record} sr ON sr.id = jr.source
              WHERE sr.userid = :userid',
            ['ctxmodule' => CONTEXT_MODULE, 'userid' => $userid]
        );

        // Table jitsi_tutoring_schedule: CONTEXT_COURSE via courseid.
        $contextlist->add_from_sql(
            'SELECT ctx.id
               FROM {context} ctx
               JOIN {jitsi_tutoring_schedule} ts ON ts.courseid = ctx.instanceid
              WHERE ts.userid = :userid AND ctx.contextlevel = :ctxcourse',
            ['ctxcourse' => CONTEXT_COURSE, 'userid' => $userid]
        );

        // Table jitsi_push_subscriptions: CONTEXT_USER.
        if ($DB->record_exists('jitsi_push_subscriptions', ['userid' => $userid])) {
            $contextlist->add_user_context($userid);
        }

        return $contextlist;
    }

    /**
     * Get the list of users who have data within a context.
     *
     * @param userlist $userlist The userlist containing the list of users who have data in this context/plugin combination.
     */
    public static function get_users_in_context(userlist $userlist) {
        $context = $userlist->get_context();

        if ($context->contextlevel == CONTEXT_MODULE) {
            // Table jitsi_usage_daily.
            $userlist->add_from_sql(
                'userid',
                'SELECT ud.userid FROM {jitsi_usage_daily} ud WHERE ud.cmid = :cmid',
                ['cmid' => $context->instanceid]
            );

            // Table jitsi_recording_segments.
            $userlist->add_from_sql(
                'userid',
                'SELECT rs.userid FROM {jitsi_recording_segments} rs WHERE rs.cmid = :cmid',
                ['cmid' => $context->instanceid]
            );

            // Table jitsi_presence: jitsiid = jitsi instance id.
            $userlist->add_from_sql(
                'userid',
                'SELECT jp.userid FROM {jitsi_presence} jp
                   JOIN {course_modules} cm ON cm.instance = jp.jitsiid
                  WHERE cm.id = :cmid AND jp.userid != 0',
                ['cmid' => $context->instanceid]
            );

            // Table jitsi_source_record: joined via jitsi_record.
            $userlist->add_from_sql(
                'userid',
                'SELECT sr.userid FROM {jitsi_source_record} sr
                   JOIN {jitsi_record} jr ON jr.source = sr.id
                   JOIN {course_modules} cm ON cm.instance = jr.jitsi
                  WHERE cm.id = :cmid',
                ['cmid' => $context->instanceid]
            );
        } else if ($context->contextlevel == CONTEXT_COURSE) {
            // Table jitsi_tutoring_schedule.
            $userlist->add_from_sql(
                'userid',
                'SELECT ts.userid FROM {jitsi_tutoring_schedule} ts WHERE ts.courseid = :courseid',
                ['courseid' => $context->instanceid]
            );
        } else if ($context->contextlevel == CONTEXT_USER) {
            // Table jitsi_push_subscriptions.
            $userlist->add_from_sql(
                'userid',
                'SELECT ps.userid FROM {jitsi_push_subscriptions} ps WHERE ps.userid = :userid',
                ['userid' => $context->instanceid]
            );
        }
    }

    /**
     * Export all user data for the specified user, in the specified contexts.
     *
     * @param approved_contextlist $contextlist The approved contexts to export information for.
     */
    public static function export_user_data(approved_contextlist $contextlist) {
        global $DB;

        $userid = $contextlist->get_user()->id;

        foreach ($contextlist->get_contexts() as $context) {
            if ($context->contextlevel == CONTEXT_MODULE) {
                // Table jitsi_usage_daily.
                $records = $DB->get_records(
                    'jitsi_usage_daily',
                    ['userid' => $userid, 'cmid' => $context->instanceid]
                );
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_usage_daily', 'jitsi')],
                        (object)['sessions' => array_values($records)]
                    );
                }

                // Table jitsi_recording_segments.
                $records = $DB->get_records(
                    'jitsi_recording_segments',
                    ['userid' => $userid, 'cmid' => $context->instanceid]
                );
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_recording_segments', 'jitsi')],
                        (object)['segments' => array_values($records)]
                    );
                }

                // Table jitsi_presence.
                $records = $DB->get_records_sql(
                    'SELECT jp.* FROM {jitsi_presence} jp
                       JOIN {course_modules} cm ON cm.instance = jp.jitsiid
                      WHERE jp.userid = :userid AND cm.id = :cmid',
                    ['userid' => $userid, 'cmid' => $context->instanceid]
                );
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_presence', 'jitsi')],
                        (object)['presence' => array_values($records)]
                    );
                }

                // Table jitsi_source_record.
                $records = $DB->get_records_sql(
                    'SELECT sr.id, sr.link, sr.timecreated, sr.userid, sr.type
                       FROM {jitsi_source_record} sr
                       JOIN {jitsi_record} jr ON jr.source = sr.id
                       JOIN {course_modules} cm ON cm.instance = jr.jitsi
                      WHERE sr.userid = :userid AND cm.id = :cmid',
                    ['userid' => $userid, 'cmid' => $context->instanceid]
                );
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_source_record', 'jitsi')],
                        (object)['recordings' => array_values($records)]
                    );
                }
            } else if ($context->contextlevel == CONTEXT_COURSE) {
                // Table jitsi_tutoring_schedule.
                $records = $DB->get_records(
                    'jitsi_tutoring_schedule',
                    ['userid' => $userid, 'courseid' => $context->instanceid]
                );
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_tutoring_schedule', 'jitsi')],
                        (object)['schedule' => array_values($records)]
                    );
                }
            } else if ($context->contextlevel == CONTEXT_USER) {
                // Table jitsi_push_subscriptions.
                $records = $DB->get_records('jitsi_push_subscriptions', ['userid' => $userid]);
                if ($records) {
                    writer::with_context($context)->export_data(
                        [get_string('privacy:metadata:jitsi_push_subscriptions', 'jitsi')],
                        (object)['subscriptions' => array_values($records)]
                    );
                }
            }
        }
    }

    /**
     * Delete all data for all users in the specified context.
     *
     * @param \context $context The specific context to delete data for.
     */
    public static function delete_data_for_all_users_in_context(\context $context) {
        global $DB;

        if ($context->contextlevel == CONTEXT_MODULE) {
            $cmid = $context->instanceid;
            $DB->delete_records('jitsi_usage_daily', ['cmid' => $cmid]);
            $DB->delete_records('jitsi_recording_segments', ['cmid' => $cmid]);
            $DB->delete_records_sql(
                'DELETE FROM {jitsi_presence}
                  WHERE jitsiid IN (SELECT cm.instance FROM {course_modules} cm WHERE cm.id = :cmid)',
                ['cmid' => $cmid]
            );
            // Anonymise creator rather than delete the recording row.
            $DB->execute(
                'UPDATE {jitsi_source_record} SET userid = 0
                  WHERE id IN (
                      SELECT jr.source FROM {jitsi_record} jr
                        JOIN {course_modules} cm ON cm.instance = jr.jitsi
                       WHERE cm.id = :cmid)',
                ['cmid' => $cmid]
            );
        } else if ($context->contextlevel == CONTEXT_COURSE) {
            $DB->delete_records('jitsi_tutoring_schedule', ['courseid' => $context->instanceid]);
        } else if ($context->contextlevel == CONTEXT_USER) {
            $DB->delete_records('jitsi_push_subscriptions', ['userid' => $context->instanceid]);
        }
    }

    /**
     * Delete all user data for the specified user, in the specified contexts.
     *
     * @param approved_contextlist $contextlist The approved contexts and user information to delete information for.
     */
    public static function delete_data_for_user(approved_contextlist $contextlist) {
        global $DB;

        $userid = $contextlist->get_user()->id;

        foreach ($contextlist->get_contexts() as $context) {
            if ($context->contextlevel == CONTEXT_MODULE) {
                $cmid = $context->instanceid;
                $DB->delete_records('jitsi_usage_daily', ['userid' => $userid, 'cmid' => $cmid]);
                $DB->delete_records('jitsi_recording_segments', ['userid' => $userid, 'cmid' => $cmid]);
                $DB->delete_records_sql(
                    'DELETE FROM {jitsi_presence}
                      WHERE userid = :userid
                        AND jitsiid IN (SELECT cm.instance FROM {course_modules} cm WHERE cm.id = :cmid)',
                    ['userid' => $userid, 'cmid' => $cmid]
                );
                $DB->execute(
                    'UPDATE {jitsi_source_record} SET userid = 0
                      WHERE userid = :userid
                        AND id IN (
                            SELECT jr.source FROM {jitsi_record} jr
                              JOIN {course_modules} cm ON cm.instance = jr.jitsi
                             WHERE cm.id = :cmid)',
                    ['userid' => $userid, 'cmid' => $cmid]
                );
            } else if ($context->contextlevel == CONTEXT_COURSE) {
                $DB->delete_records(
                    'jitsi_tutoring_schedule',
                    ['userid' => $userid, 'courseid' => $context->instanceid]
                );
            } else if ($context->contextlevel == CONTEXT_USER) {
                $DB->delete_records('jitsi_push_subscriptions', ['userid' => $userid]);
            }
        }
    }

    /**
     * Delete multiple users within a single context.
     *
     * @param approved_userlist $userlist The approved context and user information to delete information for.
     */
    public static function delete_data_for_users_in_context(approved_userlist $userlist) {
        global $DB;

        $context = $userlist->get_context();
        $userids = $userlist->get_userids();
        if (empty($userids)) {
            return;
        }

        [$insql, $inparams] = $DB->get_in_or_equal($userids, SQL_PARAMS_NAMED);

        if ($context->contextlevel == CONTEXT_MODULE) {
            $cmid = $context->instanceid;
            $DB->delete_records_select(
                'jitsi_usage_daily',
                "userid $insql AND cmid = :cmid",
                array_merge($inparams, ['cmid' => $cmid])
            );
            $DB->delete_records_select(
                'jitsi_recording_segments',
                "userid $insql AND cmid = :cmid",
                array_merge($inparams, ['cmid' => $cmid])
            );
            $DB->delete_records_sql(
                "DELETE FROM {jitsi_presence}
                  WHERE userid $insql
                    AND jitsiid IN (SELECT cm.instance FROM {course_modules} cm WHERE cm.id = :cmid)",
                array_merge($inparams, ['cmid' => $cmid])
            );
            $DB->execute(
                "UPDATE {jitsi_source_record} SET userid = 0
                  WHERE userid $insql
                    AND id IN (
                        SELECT jr.source FROM {jitsi_record} jr
                          JOIN {course_modules} cm ON cm.instance = jr.jitsi
                         WHERE cm.id = :cmid)",
                array_merge($inparams, ['cmid' => $cmid])
            );
        } else if ($context->contextlevel == CONTEXT_COURSE) {
            $DB->delete_records_select(
                'jitsi_tutoring_schedule',
                "userid $insql AND courseid = :courseid",
                array_merge($inparams, ['courseid' => $context->instanceid])
            );
        } else if ($context->contextlevel == CONTEXT_USER) {
            $DB->delete_records_select('jitsi_push_subscriptions', "userid $insql", $inparams);
        }
    }
}
