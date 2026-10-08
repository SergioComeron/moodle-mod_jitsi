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

namespace Google\Service\Storage;

class ObjectFullContext extends \Google\Model
{
  /**
   * Custom object context.
   */
  public const TYPE_CUSTOM = 'CUSTOM';
  /**
   * The time at which the object context was created. This value is in RFC 3339
   * format.
   *
   * @var string
   */
  public $createTime;
  /**
   * The extended data of the object context.
   *
   * @var array[]
   */
  public $extendedData;
  /**
   * The key of the object context.
   *
   * @var string
   */
  public $key;
  /**
   * The kind of item this is. For ObjectFullContext, this is always
   * storage#objectFullContext.
   *
   * @var string
   */
  public $kind;
  /**
   * The type of the object context.
   *
   * @var string
   */
  public $type;
  /**
   * The time at which the object context was last updated. This value is in RFC
   * 3339 format.
   *
   * @var string
   */
  public $updateTime;
  /**
   * The value of the object context.
   *
   * @var string
   */
  public $value;

  /**
   * The time at which the object context was created. This value is in RFC 3339
   * format.
   *
   * @param string $createTime
   */
  public function setCreateTime($createTime)
  {
    $this->createTime = $createTime;
  }
  /**
   * @return string
   */
  public function getCreateTime()
  {
    return $this->createTime;
  }
  /**
   * The extended data of the object context.
   *
   * @param array[] $extendedData
   */
  public function setExtendedData($extendedData)
  {
    $this->extendedData = $extendedData;
  }
  /**
   * @return array[]
   */
  public function getExtendedData()
  {
    return $this->extendedData;
  }
  /**
   * The key of the object context.
   *
   * @param string $key
   */
  public function setKey($key)
  {
    $this->key = $key;
  }
  /**
   * @return string
   */
  public function getKey()
  {
    return $this->key;
  }
  /**
   * The kind of item this is. For ObjectFullContext, this is always
   * storage#objectFullContext.
   *
   * @param string $kind
   */
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  /**
   * @return string
   */
  public function getKind()
  {
    return $this->kind;
  }
  /**
   * The type of the object context.
   *
   * Accepted values: CUSTOM
   *
   * @param self::TYPE_* $type
   */
  public function setType($type)
  {
    $this->type = $type;
  }
  /**
   * @return self::TYPE_*
   */
  public function getType()
  {
    return $this->type;
  }
  /**
   * The time at which the object context was last updated. This value is in RFC
   * 3339 format.
   *
   * @param string $updateTime
   */
  public function setUpdateTime($updateTime)
  {
    $this->updateTime = $updateTime;
  }
  /**
   * @return string
   */
  public function getUpdateTime()
  {
    return $this->updateTime;
  }
  /**
   * The value of the object context.
   *
   * @param string $value
   */
  public function setValue($value)
  {
    $this->value = $value;
  }
  /**
   * @return string
   */
  public function getValue()
  {
    return $this->value;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ObjectFullContext::class, 'Google_Service_Storage_ObjectFullContext');
