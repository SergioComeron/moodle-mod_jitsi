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

namespace mod_jitsi;

defined('MOODLE_INTERNAL') || die();

/**
 * Schema lint tests for mod_jitsi install.xml.
 *
 * Prevents XMLDB warnings caused by CHAR/VARCHAR NOT NULL columns with
 * empty-string defaults, which Moodle does not allow.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class xmldb_schema_test extends \advanced_testcase {

    /** @var \xmldb_structure Parsed install.xml structure. */
    private \xmldb_structure $structure;

    protected function setUp(): void {
        global $CFG;
        parent::setUp();

        $xmlfile = new \xmldb_file($CFG->dirroot . '/mod/jitsi/db/install.xml');
        $xmlfile->loadXMLStructure();
        $this->structure = $xmlfile->getStructure();
    }

    /**
     * CHAR/VARCHAR NOT NULL columns must not have an empty-string default.
     *
     * Moodle XMLDB automatically strips such defaults and logs a debugging()
     * warning (visible via local_adminer and the performance overview page).
     *
     * @covers db/install.xml
     */
    public function test_no_char_notnull_with_empty_default(): void {
        $violations = [];

        foreach ($this->structure->getTables() as $table) {
            foreach ($table->getFields() as $field) {
                $ischar = in_array($field->getType(), [XMLDB_TYPE_CHAR, XMLDB_TYPE_TEXT], true);
                $isnotnull = (bool)$field->getNotNull();
                $default = $field->getDefault();

                if ($ischar && $isnotnull && $default === '') {
                    $violations[] = $table->getName() . '.' . $field->getName();
                }
            }
        }

        $this->assertEmpty(
            $violations,
            'CHAR/VARCHAR NOT NULL columns with DEFAULT \'\' found in install.xml ' .
            '(Moodle XMLDB does not allow this): ' . implode(', ', $violations)
        );
    }
}
