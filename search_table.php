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
 * Defines the accept event.
 *
 * @package    mod_jitsi
 * @copyright  2023 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();
require_once($CFG->libdir . '/tablelib.php');
require_once($CFG->libdir . '/adminlib.php');

/**
 * Extend the standard table class for jitsi.
 */
class mod_search_table extends table_sql {
    /**
     * Constructor
     * @param int $uniqueid all tables have to have a unique id, this is used
     *      as a key when storing table properties like sort order in the session.
     */
    public function __construct($uniqueid) {
        parent::__construct($uniqueid);
        // Define the list of columns to show.
        $columns = ['id', 'link', 'jitsi', 'course', 'account', 'userid', 'timecreated', 'maxparticipants', 'deleted'];
        $this->define_columns($columns);

        // Define the titles of columns to show in header.
        $headers = ['Id', 'Link', 'Jitsi', 'Course', 'Account', 'User', 'Date', 'Max participants', 'Deleted'];
        $this->define_headers($headers);
    }

    /**
     * This function is called for each data row to allow processing of the
     * username value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_userid($values) {
        global $DB;
        $user = $DB->get_record('user', ['id' => $values->userid]);
        $urluser = new moodle_url('/user/profile.php', ['id' => $user->id]);
        return "<a href=" . $urluser . " data-toggle=\"tooltip\" data-placement=\"top\" title=\""
            . $user->username . "\">" . $user->firstname . " " . $user->lastname . '</a>';
    }

    /**
     * This function is called for each data row to allow processing of the
     * username value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_timecreated($values) {
        // If the data is being downloaded than we don't want to show HTML.
        return userdate($values->timecreated);
    }

    /**
     * This function is called for each data row to allow processing of the
     * account value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_account($values) {
        global $DB;
        $acount = $DB->get_record('jitsi_record_account', ['id' => $values->account]);
        return $acount->name;
    }

    /**
     * This function is called for each data row to allow processing of the
     * account value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_course($values) {
        global $DB;
        $coursemodule = get_coursemodule_from_instance('jitsi', $values->jitsi);
        $urlcourse = new moodle_url('/course/view.php', ['id' => $coursemodule->course]);
        $course = $DB->get_record('course', ['id' => $coursemodule->course]);
        return "<a href=" . $urlcourse . " data-toggle=\"tooltip\" data-placement=\"top\" title=\"" . $course->fullname . "\">" .
        $course->shortname . "</a></h6>";
    }

    /**
     * This function is called for each data row to allow processing of the
     * link value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_link($values) {
        $thumb = 'https://img.youtube.com/vi/' . $values->link . '/default_live.jpg';
        return '<a href="https://youtu.be/' . $values->link . '" target="_blank" rel="noopener">'
            . '<img src="' . $thumb . '" alt="' . s(get_string('recordingthumbnail', 'jitsi')) . '" /></a>';
    }

    /**
     * This function is called for each data row to allow processing of the
     * delete value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_jitsi($values) {
        global $DB, $OUTPUT;
        $jitsi = $DB->get_record('jitsi', ['id' => $values->jitsi]);
        $coursemodule = get_coursemodule_from_instance('jitsi', $values->jitsi);
        $urljitsiparams = ['id' => $coursemodule->id];
        $urljitsi = new moodle_url('/mod/jitsi/view.php', $urljitsiparams);
        return "<a href=" . $urljitsi . " >" . $jitsi->name . "</a>";
    }

    /**
     * This function is called for each data row to allow processing of the
     * account value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_deleted($values) {
        if ($values->deleted == 1) {
            return get_string('yes');
        } else {
            return get_string('no');
        }
        return $acount->name;
    }
}
