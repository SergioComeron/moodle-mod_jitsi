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
 * Web service local plugin template external functions and service definitions.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// We defined the web service functions to install.
defined('MOODLE_INTERNAL') || die();

$functions = [
        'mod_jitsi_state_record' => [
                'classname' => 'mod_jitsi\external\state_record',
                'methodname' => 'execute',
                'description' => 'State session recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_participating_session' => [
                'classname' => 'mod_jitsi\external\participating_session',
                'methodname' => 'execute',
                'description' => 'State session recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_press_record_button' => [
                'classname' => 'mod_jitsi\external\press_record_button',
                'methodname' => 'execute',
                'description' => 'User press record button',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_press_button_cam' => [
                'classname' => 'mod_jitsi\external\press_button_cam',
                'methodname' => 'execute',
                'description' => 'User press a camera button',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_press_button_desktop' => [
                'classname' => 'mod_jitsi\external\press_button_desktop',
                'methodname' => 'execute',
                'description' => 'User press a desktop button',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_press_button_end' => [
                'classname' => 'mod_jitsi\external\press_button_end',
                'methodname' => 'execute',
                'description' => 'User press a end button',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_press_button_microphone' => [
                'classname' => 'mod_jitsi\external\press_button_microphone',
                'methodname' => 'execute',
                'description' => 'User press a microphone button',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_create_stream' => [
                'classname' => 'mod_jitsi\external\create_stream',
                'methodname' => 'execute',
                'description' => 'Create a stream',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_view_jitsi' => [
                'classname' => 'mod_jitsi\external\view_jitsi',
                'methodname' => 'execute',
                'description' => 'Trigger the course module viewed event.',
                'type' => 'write',
                'capabilities' => 'mod/jitsi:view',
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_delete_record_youtube' => [
                'classname' => 'mod_jitsi\external\delete_record_youtube',
                'methodname' => 'execute',
                'description' => 'Delete video from youtube when problem',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_send_error' => [
                'classname' => 'mod_jitsi\external\send_error',
                'methodname' => 'execute',
                'description' => 'Send error to admin',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_stop_stream' => [
                'classname' => 'mod_jitsi\external\stop_stream',
                'methodname' => 'execute',
                'description' => 'Stop stream',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_stop_stream_byerror' => [
                'classname' => 'mod_jitsi\external\stop_stream_byerror',
                'methodname' => 'execute',
                'description' => 'Stop stream by error',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_update_participants' => [
                'classname' => 'mod_jitsi\external\update_participants',
                'methodname' => 'execute',
                'description' => 'Update Participatns',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_log_error' => [
                'classname' => 'mod_jitsi\external\log_error',
                'methodname' => 'execute',
                'description' => 'Log error',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_getminutesfromlastconexion' => [
                'classname' => 'mod_jitsi\external\getminutesfromlastconexion',
                'methodname' => 'execute',
                'description' => 'Get minutes from last conexion',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_stop_stream_noauthor' => [
                'classname' => 'mod_jitsi\external\stop_stream_noauthor',
                'methodname' => 'execute',
                'description' => 'Stop stream by error',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_save_recording_link' => [
                'classname' => 'mod_jitsi\external\save_recording_link',
                'methodname' => 'execute',
                'description' => 'Save a recording link received from Jitsi recordingLinkAvailable event',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
                'services' => [MOODLE_OFFICIAL_MOBILE_SERVICE, 'local_mobile'],
        ],

        'mod_jitsi_search_shared_sessions' => [
                'classname' => 'mod_jitsi\external\search_shared_sessions',
                'methodname' => 'execute',
                'description' => 'Search for Jitsi master sessions available to join as a shared session',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],

        'mod_jitsi_queue_ai_summary' => [
                'classname' => 'mod_jitsi\external\queue_ai_summary',
                'methodname' => 'execute',
                'description' => 'Queue an AI summary generation task for a GCS recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],

        'mod_jitsi_queue_ai_quiz' => [
                'classname' => 'mod_jitsi\external\queue_ai_quiz',
                'methodname' => 'execute',
                'description' => 'Queue an AI true/false quiz generation task for a GCS recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],

        'mod_jitsi_queue_ai_transcription' => [
                'classname' => 'mod_jitsi\external\queue_ai_transcription',
                'methodname' => 'execute',
                'description' => 'Queue an AI transcription generation task for a GCS recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],

        'mod_jitsi_search_coursemates' => [
                'classname' => 'mod_jitsi\external\search_coursemates',
                'methodname' => 'execute',
                'description' => 'Search for users who share at least one course with the current user',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_register_push_subscription' => [
                'classname' => 'mod_jitsi\external\register_push_subscription',
                'methodname' => 'execute',
                'description' => 'Register a Web Push subscription for the current user',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_unregister_push_subscription' => [
                'classname' => 'mod_jitsi\external\unregister_push_subscription',
                'methodname' => 'execute',
                'description' => 'Unregister a Web Push subscription',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_check_incoming_call' => [
                'classname' => 'mod_jitsi\external\check_incoming_call',
                'methodname' => 'execute',
                'description' => 'Check for incoming private session calls',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_get_tutoring_schedule' => [
                'classname' => 'mod_jitsi\external\get_tutoring_schedule',
                'methodname' => 'execute',
                'description' => 'Get the current user tutoring schedule',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_save_tutoring_slot' => [
                'classname' => 'mod_jitsi\external\save_tutoring_slot',
                'methodname' => 'execute',
                'description' => 'Save a tutoring schedule slot',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_delete_tutoring_slot' => [
                'classname' => 'mod_jitsi\external\delete_tutoring_slot',
                'methodname' => 'execute',
                'description' => 'Delete a tutoring schedule slot',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_get_teacher_schedule' => [
                'classname' => 'mod_jitsi\external\get_teacher_schedule',
                'methodname' => 'execute',
                'description' => 'Get tutoring schedule for a teacher visible to current user',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_log_recording_view' => [
                'classname' => 'mod_jitsi\external\log_recording_view',
                'methodname' => 'execute',
                'description' => 'Log that the current user played a GCS recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_save_recording_segments' => [
                'classname' => 'mod_jitsi\external\save_recording_segments',
                'methodname' => 'execute',
                'description' => 'Save and merge watched segments for a GCS recording',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => true,
        ],
        'mod_jitsi_get_bucket_viewers' => [
                'classname' => 'mod_jitsi\external\get_bucket_viewers',
                'methodname' => 'execute',
                'description' => 'Get list of users who watched a specific time bucket of a recording',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => true,
        ],

        'mod_jitsi_presence_join' => [
                'classname' => 'mod_jitsi\external\presence_join',
                'methodname' => 'execute',
                'description' => 'Register participant presence on join',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_presence_leave' => [
                'classname' => 'mod_jitsi\external\presence_leave',
                'methodname' => 'execute',
                'description' => 'Remove participant presence on leave',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_presence_heartbeat' => [
                'classname' => 'mod_jitsi\external\presence_heartbeat',
                'methodname' => 'execute',
                'description' => 'Update presence heartbeat timestamp',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_get_presence_count' => [
                'classname' => 'mod_jitsi\external\get_presence_count',
                'methodname' => 'execute',
                'description' => 'Get active participant count from presence table',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_get_presence_users' => [
                'classname' => 'mod_jitsi\external\get_presence_users',
                'methodname' => 'execute',
                'description' => 'Get names of active participants from presence table',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_set_jibri_recording' => [
                'classname' => 'mod_jitsi\external\set_jibri_recording',
                'methodname' => 'execute',
                'description' => 'Set GCP recording status on a jitsi session',
                'type' => 'write',
                'ajax' => true,
                'loginrequired' => false,
        ],

        'mod_jitsi_get_jibri_recording' => [
                'classname' => 'mod_jitsi\external\get_jibri_recording',
                'methodname' => 'execute',
                'description' => 'Get GCP recording status for a jitsi session',
                'type' => 'read',
                'ajax' => true,
                'loginrequired' => false,
        ],
];
