<?php
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

namespace Google\Service\Compute;

class RegexRewrite extends \Google\Model
{
  /**
   * Required. The regular expression used to match against the URL path. It
   * uses RE2 syntax with the following constraints:              - Any single
   * character operators      - Groups are allowed to have only submatch
   * operator inside      - Groups are allowed only without any char repetition,
   * e.g.      .*      - Any char repetition, e.g. .*, is      only allowed to
   * be used in a single regex together with:                            - Empty
   * string operators             - Other repetitions             - Ranges
   * - Repetitions of ranges                       - Ranges are only allowed to
   * have:                            - Character range             - Digits
   * range             - Symbols listed in characters allowed for ranges
   *
   * @var string
   */
  public $pathPattern;
  /**
   * Required. Required when path pattern is specified. Used to rewrite matching
   * parts of the path.
   *
   * @var string
   */
  public $pathSubstitution;

  /**
   * Required. The regular expression used to match against the URL path. It
   * uses RE2 syntax with the following constraints:              - Any single
   * character operators      - Groups are allowed to have only submatch
   * operator inside      - Groups are allowed only without any char repetition,
   * e.g.      .*      - Any char repetition, e.g. .*, is      only allowed to
   * be used in a single regex together with:                            - Empty
   * string operators             - Other repetitions             - Ranges
   * - Repetitions of ranges                       - Ranges are only allowed to
   * have:                            - Character range             - Digits
   * range             - Symbols listed in characters allowed for ranges
   *
   * @param string $pathPattern
   */
  public function setPathPattern($pathPattern)
  {
    $this->pathPattern = $pathPattern;
  }
  /**
   * @return string
   */
  public function getPathPattern()
  {
    return $this->pathPattern;
  }
  /**
   * Required. Required when path pattern is specified. Used to rewrite matching
   * parts of the path.
   *
   * @param string $pathSubstitution
   */
  public function setPathSubstitution($pathSubstitution)
  {
    $this->pathSubstitution = $pathSubstitution;
  }
  /**
   * @return string
   */
  public function getPathSubstitution()
  {
    return $this->pathSubstitution;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(RegexRewrite::class, 'Google_Service_Compute_RegexRewrite');
