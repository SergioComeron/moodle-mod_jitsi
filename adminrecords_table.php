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
class mod_adminrecords_table extends table_sql {
    /**
     * Constructor
     * @param int $uniqueid all tables have to have a unique id, this is used
     *      as a key when storing table properties like sort order in the session.
     */
    public function __construct($uniqueid) {
        parent::__construct($uniqueid);
        // Define the list of columns to show.
        $columns = ['id', 'link', 'account', 'userid', 'timecreated', 'delete'];
        $this->define_columns($columns);

        // Define the titles of columns to show in header.
        $headers = ['Id', 'Link', 'Account', 'User', 'Date', 'Delete'];
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
        return $user->username;
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
        if (empty($values->account)) {
            return '-';
        }
        $acount = $DB->get_record('jitsi_record_account', ['id' => $values->account]);
        return $acount ? $acount->name : '-';
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
        if ((int)$values->type === 1) {
            // Jibri/GCS recording — link is a full URL.
            return '<a href="' . s($values->link) . '" target="_blank">' . s($values->link) . '</a>';
        }
        return '<a href="https://youtu.be/' . s($values->link) . '" target="_blank">' . s($values->link) . '</a>';
    }

    /**
     * This function is called for each data row to allow processing of the
     * delete value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_delete($values) {
        global $DB, $OUTPUT;

        if (!isDeletable($values->id)) {
            return '';
        }

        // Jibri/GCS recordings (type=1) don't need a YouTube token — deletable directly.
        if ((int)$values->type === 1) {
            $deleteurl = new moodle_url('/mod/jitsi/adminrecord.php', [
                'deletejitsisourceid' => $values->id,
                'sesskey'             => sesskey(),
            ]);
            $deleteicon = new pix_icon('t/delete', get_string('delete'));
            return $OUTPUT->action_icon(
                $deleteurl,
                $deleteicon,
                new confirm_action(get_string('deletesourceq', 'jitsi'))
            );
        }

        // YouTube recordings need a valid access token.
        $acount = $DB->get_record('jitsi_record_account', ['id' => $values->account]);
        if ($acount && $acount->clientaccesstoken != null) {
            $deleteurl = new moodle_url('/mod/jitsi/adminrecord.php', [
                'deletejitsisourceid' => $values->id,
                'sesskey'             => sesskey(),
            ]);
            $deleteicon = new pix_icon('t/delete', get_string('delete'));
            return $OUTPUT->action_icon(
                $deleteurl,
                $deleteicon,
                new confirm_action(get_string('deletesourceq', 'jitsi'))
            );
        }

        return get_string('notdeletable', 'jitsi');
    }
}
