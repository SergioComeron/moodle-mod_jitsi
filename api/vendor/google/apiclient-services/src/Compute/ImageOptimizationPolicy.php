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

class ImageOptimizationPolicy extends \Google\Model
{
  /**
   * Query parameters for image optimization are ignored.
   */
  public const QUERY_PARAMETER_INTERPRETATION_DISABLED = 'DISABLED';
  /**
   * Query parameters for image optimization are interpreted.
   */
  public const QUERY_PARAMETER_INTERPRETATION_ENABLED = 'ENABLED';
  /**
   * Default value. This field value translates to the default behavior, which
   * is to ignore query parameters for image optimization.
   */
  public const QUERY_PARAMETER_INTERPRETATION_QUERY_PARAMETER_INTERPRETATION_UNSPECIFIED = 'QUERY_PARAMETER_INTERPRETATION_UNSPECIFIED';
  /**
   * Specifies whether to interpret query parameters for image optimization.
   *
   * @var string
   */
  public $queryParameterInterpretation;

  /**
   * Specifies whether to interpret query parameters for image optimization.
   *
   * Accepted values: DISABLED, ENABLED,
   * QUERY_PARAMETER_INTERPRETATION_UNSPECIFIED
   *
   * @param self::QUERY_PARAMETER_INTERPRETATION_* $queryParameterInterpretation
   */
  public function setQueryParameterInterpretation($queryParameterInterpretation)
  {
    $this->queryParameterInterpretation = $queryParameterInterpretation;
  }
  /**
   * @return self::QUERY_PARAMETER_INTERPRETATION_*
   */
  public function getQueryParameterInterpretation()
  {
    return $this->queryParameterInterpretation;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ImageOptimizationPolicy::class, 'Google_Service_Compute_ImageOptimizationPolicy');
