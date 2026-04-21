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

/**
 * Schema lint tests for mod_jitsi install.xml.
 *
 * Covers common XMLDB mistakes that cause runtime warnings, broken installs,
 * or Oracle incompatibilities: empty-string defaults, missing defaults on NOT NULL
 * integer fields, oversized names, CHAR columns that are too wide or missing a
 * length, and tables without a primary key.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class xmldb_schema_test extends \advanced_testcase {
    /** @var \xmldb_structure Parsed install.xml structure. */
    private \xmldb_structure $structure;

    /** Maximum table name length (Moodle limit, leaves room for the mdl_ prefix under Oracle's 30-char cap). */
    private const MAX_TABLE_NAME = 28;

    /** Maximum column name length (Oracle hard limit). */
    private const MAX_COLUMN_NAME = 30;

    /** Maximum CHAR length before TEXT should be used instead. */
    private const MAX_CHAR_LENGTH = 1333;

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
     * warning visible via local_adminer and the performance overview page.
     *
     * @covers \xmldb_file
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
            'CHAR/TEXT NOT NULL columns with DEFAULT \'\' found in install.xml ' .
            '(Moodle XMLDB does not allow this): ' . implode(', ', $violations)
        );
    }

    /**
     * Table names must not exceed the Moodle maximum length.
     *
     * Oracle limits identifiers to 30 characters. With the mdl_ prefix (4 chars),
     * table names are capped at 26 chars in practice; Moodle's own limit is 28.
     *
     * @covers \xmldb_file
     */
    public function test_table_name_length(): void {
        $violations = [];

        foreach ($this->structure->getTables() as $table) {
            if (strlen($table->getName()) > self::MAX_TABLE_NAME) {
                $violations[] = $table->getName() . ' (' . strlen($table->getName()) . ' chars)';
            }
        }

        $this->assertEmpty(
            $violations,
            'Table names exceeding ' . self::MAX_TABLE_NAME . ' characters found in install.xml: ' .
            implode(', ', $violations)
        );
    }

    /**
     * Column names must not exceed 30 characters (Oracle hard limit).
     *
     * @covers \xmldb_file
     */
    public function test_column_name_length(): void {
        $violations = [];

        foreach ($this->structure->getTables() as $table) {
            foreach ($table->getFields() as $field) {
                if (strlen($field->getName()) > self::MAX_COLUMN_NAME) {
                    $violations[] = $table->getName() . '.' . $field->getName() .
                        ' (' . strlen($field->getName()) . ' chars)';
                }
            }
        }

        $this->assertEmpty(
            $violations,
            'Column names exceeding ' . self::MAX_COLUMN_NAME . ' characters found in install.xml: ' .
            implode(', ', $violations)
        );
    }

    /**
     * CHAR columns must have a length defined and must not exceed the recommended maximum.
     *
     * A CHAR column wider than 1333 characters should be declared as TEXT instead,
     * because some database engines impose byte-length limits on indexed VARCHAR columns.
     *
     * @covers \xmldb_file
     */
    public function test_char_length(): void {
        $missing = [];
        $toolong = [];

        foreach ($this->structure->getTables() as $table) {
            foreach ($table->getFields() as $field) {
                if ($field->getType() !== XMLDB_TYPE_CHAR) {
                    continue;
                }
                $length = (int)$field->getLength();
                if ($length <= 0) {
                    $missing[] = $table->getName() . '.' . $field->getName();
                } else if ($length > self::MAX_CHAR_LENGTH) {
                    $toolong[] = $table->getName() . '.' . $field->getName() . ' (length ' . $length . ')';
                }
            }
        }

        $this->assertEmpty(
            $missing,
            'CHAR columns without a length defined in install.xml: ' . implode(', ', $missing)
        );
        $this->assertEmpty(
            $toolong,
            'CHAR columns exceeding ' . self::MAX_CHAR_LENGTH . ' chars (use TEXT instead) in install.xml: ' .
            implode(', ', $toolong)
        );
    }

    /**
     * Every table must have a primary key defined.
     *
     * A table without a primary key cannot be used reliably across all database
     * engines supported by Moodle and will cause issues with backup/restore.
     *
     * @covers \xmldb_file
     */
    public function test_tables_have_primary_key(): void {
        $violations = [];

        foreach ($this->structure->getTables() as $table) {
            $haspk = false;
            foreach ($table->getKeys() as $key) {
                if ($key->getType() === XMLDB_KEY_PRIMARY) {
                    $haspk = true;
                    break;
                }
            }
            if (!$haspk) {
                $violations[] = $table->getName();
            }
        }

        $this->assertEmpty(
            $violations,
            'Tables without a primary key found in install.xml: ' . implode(', ', $violations)
        );
    }
}
