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

class DynamicCompressionPolicy extends \Google\Model
{
  /**
   * Automatically uses the best compression based on the Accept-Encoding header
   * sent by the client.
   */
  public const COMPRESSION_MODE_AUTOMATIC = 'AUTOMATIC';
  /**
   * Disables compression. Existing compressed responses cached by Cloud CDN
   * will not be served to clients.
   */
  public const COMPRESSION_MODE_DISABLED = 'DISABLED';
  /**
   * Compress text responses using Brotli or gzip compression, based on the
   * client's Accept-Encoding header.
   *
   * @var string
   */
  public $compressionMode;

  /**
   * Compress text responses using Brotli or gzip compression, based on the
   * client's Accept-Encoding header.
   *
   * Accepted values: AUTOMATIC, DISABLED
   *
   * @param self::COMPRESSION_MODE_* $compressionMode
   */
  public function setCompressionMode($compressionMode)
  {
    $this->compressionMode = $compressionMode;
  }
  /**
   * @return self::COMPRESSION_MODE_*
   */
  public function getCompressionMode()
  {
    return $this->compressionMode;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(DynamicCompressionPolicy::class, 'Google_Service_Compute_DynamicCompressionPolicy');
