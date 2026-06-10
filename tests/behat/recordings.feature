@mod @mod_jitsi @javascript
Feature: Manage recording links in the recordings tab
  In order to share session recordings with students
  As a teacher
  I need to add, list and remove external recording links over AJAX

  Background:
    Given the following "courses" exist:
      | fullname | shortname | category |
      | Course 1 | C1        | 0        |
    And the following "users" exist:
      | username | firstname | lastname | email                |
      | teacher1 | Teacher   | One      | teacher1@example.com |
    And the following "course enrolments" exist:
      | user     | course | role           |
      | teacher1 | C1     | editingteacher |
    And the following "activities" exist:
      | activity | name           | intro      | course | idnumber |
      | jitsi    | Recorded Jitsi | Rec intro  | C1     | jitsi1   |

  Scenario: A teacher adds an external recording link and then removes it
    Given I am on the "Recorded Jitsi" "jitsi activity" page logged in as teacher1
    When I click on "Recordings" "link"
    And I set the field "Recording URL" to "https://example.com/lesson1.mp4"
    And I set the field "Recording name (optional)" to "Lesson 1"
    And I click on "Add recording link" "button"
    Then I should see "Lesson 1"
    And I should not see "No recordings available"

    When I click on "[data-action='delete']" "css_element"
    And I click on "Delete" "button" in the "Confirm" "dialogue"
    Then I should see "No recordings available"
    And I should not see "Lesson 1"
