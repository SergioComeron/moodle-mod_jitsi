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
 * Library of interface functions and constants for module jitsi
 *
 * All the core Moodle functions, neeeded to allow the module to work
 * integrated in Moodle should be placed here.
 *
 * All the jitsi specific functions, needed to implement all the module
 * logic, should go to locallib.php. This will help to save some memory when
 * Moodle is performing actions across all modules.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/* Moodle core API */
defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/deprecatedlib.php');


/**
 * Returns the information on whether the module supports a feature
 *
 * See plugin_supports() for more info.
 *
 * @param string $feature FEATURE_xx constant for requested feature
 * @return mixed true if the feature is supported, null if unknown
 */
function jitsi_supports($feature) {
    global $CFG;
    if ($CFG->branch >= 400) {
        switch ($feature) {
            case FEATURE_MOD_INTRO:
                return true;
            case FEATURE_SHOW_DESCRIPTION:
                return true;
            case FEATURE_BACKUP_MOODLE2:
                return true;
            case FEATURE_COMPLETION_HAS_RULES:
                return true;
            case FEATURE_MOD_PURPOSE:
                return MOD_PURPOSE_COMMUNICATION;
            default:
                return null;
        }
    } else {
        switch ($feature) {
            case FEATURE_MOD_INTRO:
                return true;
            case FEATURE_SHOW_DESCRIPTION:
                return true;
            case FEATURE_BACKUP_MOODLE2:
                return true;
            case FEATURE_COMPLETION_HAS_RULES:
                return true;
            default:
                return null;
        }
    }
}

/**
 * Saves a new instance of the jitsi into the database
 *
 * Given an object containing all the necessary data,
 * (defined by the form in mod_form.php) this function
 * will create a new instance and return the id number
 * of the new instance.
 *
 * @param stdClass $jitsi Submitted data from the form in mod_form.php
 * @param mod_jitsi_mod_form $mform The form instance itself (if needed)
 * @return int The id of the newly inserted jitsi record
 */
function jitsi_add_instance($jitsi, $mform = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');
    $time = time();
    $jitsi->timecreated = $time;
    $cmid = $jitsi->coursemodule;
    $jitsi->id = $DB->insert_record('jitsi', $jitsi);
    jitsi_update_calendar($jitsi, $cmid);
    return $jitsi->id;
}

/**
 * Updates an instance of the jitsi in the database
 *
 * Given an object containing all the necessary data,
 * (defined by the form in mod_form.php) this function
 * will update an existing instance with new data.
 *
 * @param stdClass $jitsi An object from the form in mod_form.php
 * @param mod_jitsi_mod_form $mform The form instance itself (if needed)
 * @return boolean Success/Fail
 */
function jitsi_update_instance($jitsi, $mform = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');

    $jitsi->timemodified = time();
    $jitsi->id = $jitsi->instance;
    $cmid = $jitsi->coursemodule;

    $result = $DB->update_record('jitsi', $jitsi);
    jitsi_update_calendar($jitsi, $cmid);

    return $result;
}

/**
 * This standard function will check all instances of this module
 * and make sure there are up-to-date events created for each of them.
 * If courseid = 0, then every assignment event in the site is checked, else
 * only assignment events belonging to the course specified are checked.
 *
 * @param int $courseid
 * @param int|stdClass $instance Jitsi module instance or ID.
 * @param int|stdClass $cm Course module object or ID.
 * @return bool
 */
function jitsi_refresh_events($courseid = 0, $instance = null, $cm = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');

    if (isset($instance)) {
        if (!is_object($instance)) {
            $instance = $DB->get_record('jitsi', ['id' => $instance], '*', MUST_EXIST);
        }
        if (isset($cm)) {
            if (!is_object($cm)) {
                $cm = (object) ['id' => $cm];
            }
        } else {
            $cm = get_coursemodule_from_instance('jitsi', $instance->id);
        }
        jitsi_update_calendar($instance, $cm->id);
        return true;
    }

    if ($courseid) {
        if (!is_numeric($courseid)) {
            return false;
        }
        if (!$jitsis = $DB->get_records('jitsi', ['course' => $courseid])) {
            return true;
        }
    } else {
        return true;
    }

    foreach ($jitsis as $jitsi) {
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id);
        jitsi_update_calendar($jitsi, $cm->id);
    }

    return true;
}

/**
 * Removes an instance of the jitsi from the database
 *
 * Given an ID of an instance of this module,
 * this function will permanently delete the instance
 * and any data that depends on it.
 *
 * @param int $id Id of the module instance
 * @return boolean Success/Failure
 */
function jitsi_delete_instance($id) {
    global $CFG, $DB;

    if (! $jitsi = $DB->get_record('jitsi', ['id' => $id])) {
        return false;
    }

    $result = true;
    $DB->delete_records('jitsi_record', ['jitsi' => $jitsi->id]);

    if (! $DB->delete_records('jitsi', ['id' => $jitsi->id])) {
        $result = false;
    }

    return $result;
}

/**
 * Jitsi private sessions on profile user
 *
 * @param tree $tree tree
 * @param stdClass $user user
 * @param int $iscurrentuser iscurrentuser
 */
function jitsi_myprofile_navigation(core_user\output\myprofile\tree $tree, $user, $iscurrentuser) {
    global $DB, $CFG, $USER;
    if (get_config('mod_jitsi', 'privatesessions') == 1) {
        $category = new core_user\output\myprofile\category(
            'jitsi',
            get_string('jitsi', 'jitsi'),
            null,
        );
        $tree->add_category($category);
        if ($iscurrentuser == 0) {
            // Only show the call link if both users share at least one course.
            $sharedcourses = enrol_get_shared_courses($USER->id, $user->id, true);
            if (!empty($sharedcourses)) {
                $url = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $user->id]);
                $node = new core_user\output\myprofile\node(
                    'jitsi',
                    'jitsi',
                    get_string('startprivatesession', 'jitsi', $user->firstname),
                    null,
                    $url,
                );
                $tree->add_node($node);
            }
        } else {
            $url = new moodle_url('/mod/jitsi/call.php');
            $node = new core_user\output\myprofile\node(
                'jitsi',
                'jitsi',
                get_string('callsomeone', 'jitsi'),
                null,
                $url,
            );
            $tree->add_node($node);
        }
    }
    return true;
}

 /**
  * Get icon mapping for font-awesome.
  */
function mod_jitsi_get_fontawesome_icon_map() {
    return [
        'mod_forum:t/add' => 'share-alt-square',
    ];
}

/**
 * For edit record name
 * @param stdClass $itemtype - Type item
 * @param int $itemid - item id
 * @param string $newvalue - new value
 */
function mod_jitsi_inplace_editable($itemtype, $itemid, $newvalue) {
    if ($itemtype === 'recordname') {
        global $DB, $PAGE;
        $record = $DB->get_record('jitsi_record', ['id' => $itemid], '*', MUST_EXIST);
        // Must call validate_context for either system, or course or course module context.
        // This will both check access and set current context.
        $record  = $DB->get_record('jitsi_record', ['id' => $itemid], '*', MUST_EXIST);
        $jitsi   = $DB->get_record('jitsi', ['id' => $record->jitsi], '*', MUST_EXIST);
        $course  = $DB->get_record('course', ['id' => $jitsi->course], '*', MUST_EXIST);
        $cm      = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $context = context_module::instance($cm->id);
        $PAGE->set_context($context);
        // Clean input and update the record.
        $newvalue = clean_param($newvalue, PARAM_NOTAGS);
        $DB->update_record('jitsi_record', ['id' => $itemid, 'name' => $newvalue]);
        // Prepare the element for the output.
        $record->name = $newvalue;
        return new \core\output\inplace_editable(
            'mod_jitsi',
            'recordname',
            $record->id,
            true,
            format_string($record->name),
            $record->name,
            get_string('editrecordname', 'jitsi'),
            get_string('newvaluefor', 'jitsi') . format_string($record->name),
        );
    }
}

/**
 * Add a get_coursemodule_info function in case any jitsi type wants to add 'extra' information
 * for the course (see resource).
 *
 * Given a course_module object, this function returns any "extra" information that may be needed
 * when printing this activity in a course listing.  See get_array_of_activities() in course/lib.php.
 *
 * @param stdClass $coursemodule The coursemodule object (record).
 * @return cached_cm_info An object on information that the courses
 *                        will know about (most noticeably, an icon).
 */
function jitsi_get_coursemodule_info($coursemodule) {
    global $DB;

    $dbparams = ['id' => $coursemodule->instance];
    $fields = 'id, name, intro, introformat, completionminutes, timeopen, timeclose';
    if (!$jitsi = $DB->get_record('jitsi', $dbparams, $fields)) {
        return false;
    }

    $result = new cached_cm_info();
    $result->name = $jitsi->name;

    if ($coursemodule->showdescription) {
        // Convert intro to html. Do not filter cached version, filters run at display time.
        $result->content = format_module_intro('jitsi', $jitsi, $coursemodule->id, false);
    }

    // Populate the custom completion rules as key => value pairs, but only if the completion mode is 'automatic'.
    if ($coursemodule->completion == COMPLETION_TRACKING_AUTOMATIC) {
        $result->customdata['customcompletionrules']['completionminutes'] = $jitsi->completionminutes;
    }

    if ($jitsi->timeopen) {
        $result->customdata['timeopen'] = $jitsi->timeopen;
    }
    if ($jitsi->timeclose) {
        $result->customdata['timeclose'] = $jitsi->timeclose;
    }

    return $result;
}

/**
 * Callback which returns human-readable strings describing the active completion custom rules for the module instance.
 *
 * @param cm_info|stdClass $cm object with fields ->completion and ->customdata['customcompletionrules']
 * @return array $descriptions the array of descriptions for the custom rules.
 */
function mod_jitsi_get_completion_active_rule_descriptions($cm) {
    // Values will be present in cm_info, and we assume these are up to date.
    if (
        empty($cm->customdata['customcompletionrules']) ||
        $cm->completion != COMPLETION_TRACKING_AUTOMATIC
    ) {
        return [];
    }

    $descriptions = [];
    foreach ($cm->customdata['customcompletionrules'] as $key => $val) {
        switch ($key) {
            case 'completionminutes':
                if (!empty($val)) {
                    $descriptions[] = get_string('completionminutes', 'jitsi', $val);
                }
                break;
            default:
                break;
        }
    }
    return $descriptions;
}
