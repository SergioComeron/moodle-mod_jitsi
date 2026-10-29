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

namespace Google\Service\YouTube;

class ChannelContentDetailsRelatedPlaylists extends \Google\Model
{
  /**
   * The ID of the playlist that contains the channel"s favorite videos. Use the
   * [`playlistItems.insert`](https://developers.google.com/youtube/data/referen
   * ce/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://devel
   * opers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to
   * add or remove items from that list.
   *
   * @deprecated
   * @var string
   */
  public $favorites;
  /**
   * The ID of the playlist that contains the channel"s liked videos. Use the [`
   * playlistItems.insert`](https://developers.google.com/youtube/data/reference
   * /rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://develop
   * ers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to add
   * or remove items from that list.
   *
   * @var string
   */
  public $likes;
  /**
   * The ID of the playlist that contains the channel"s uploaded videos. Use the
   * [`videos.insert`](https://developers.google.com/youtube/data/reference/rest
   * /v3/videos/insert) method to upload new videos and the [`videos.delete`](ht
   * tps://developers.google.com/youtube/data/reference/rest/v3/videos/delete)
   * method to delete previously uploaded videos.
   *
   * @var string
   */
  public $uploads;
  /**
   * The ID of the playlist that contains the channel"s watch history. Use the [
   * `playlistItems.insert`](https://developers.google.com/youtube/data/referenc
   * e/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://develo
   * pers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to add
   * or remove items from that list.
   *
   * @deprecated
   * @var string
   */
  public $watchHistory;
  /**
   * The ID of the playlist that contains the channel"s watch later playlist.
   * Use the [`playlistItems.insert`](https://developers.google.com/youtube/data
   * /reference/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https
   * ://developers.google.com/youtube/data/reference/rest/v3/playlistItems/delet
   * e) to add or remove items from that list.
   *
   * @deprecated
   * @var string
   */
  public $watchLater;

  /**
   * The ID of the playlist that contains the channel"s favorite videos. Use the
   * [`playlistItems.insert`](https://developers.google.com/youtube/data/referen
   * ce/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://devel
   * opers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to
   * add or remove items from that list.
   *
   * @deprecated
   * @param string $favorites
   */
  public function setFavorites($favorites)
  {
    $this->favorites = $favorites;
  }
  /**
   * @deprecated
   * @return string
   */
  public function getFavorites()
  {
    return $this->favorites;
  }
  /**
   * The ID of the playlist that contains the channel"s liked videos. Use the [`
   * playlistItems.insert`](https://developers.google.com/youtube/data/reference
   * /rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://develop
   * ers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to add
   * or remove items from that list.
   *
   * @param string $likes
   */
  public function setLikes($likes)
  {
    $this->likes = $likes;
  }
  /**
   * @return string
   */
  public function getLikes()
  {
    return $this->likes;
  }
  /**
   * The ID of the playlist that contains the channel"s uploaded videos. Use the
   * [`videos.insert`](https://developers.google.com/youtube/data/reference/rest
   * /v3/videos/insert) method to upload new videos and the [`videos.delete`](ht
   * tps://developers.google.com/youtube/data/reference/rest/v3/videos/delete)
   * method to delete previously uploaded videos.
   *
   * @param string $uploads
   */
  public function setUploads($uploads)
  {
    $this->uploads = $uploads;
  }
  /**
   * @return string
   */
  public function getUploads()
  {
    return $this->uploads;
  }
  /**
   * The ID of the playlist that contains the channel"s watch history. Use the [
   * `playlistItems.insert`](https://developers.google.com/youtube/data/referenc
   * e/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https://develo
   * pers.google.com/youtube/data/reference/rest/v3/playlistItems/delete) to add
   * or remove items from that list.
   *
   * @deprecated
   * @param string $watchHistory
   */
  public function setWatchHistory($watchHistory)
  {
    $this->watchHistory = $watchHistory;
  }
  /**
   * @deprecated
   * @return string
   */
  public function getWatchHistory()
  {
    return $this->watchHistory;
  }
  /**
   * The ID of the playlist that contains the channel"s watch later playlist.
   * Use the [`playlistItems.insert`](https://developers.google.com/youtube/data
   * /reference/rest/v3/playlistItems/insert) and [`playlistItems.delete`](https
   * ://developers.google.com/youtube/data/reference/rest/v3/playlistItems/delet
   * e) to add or remove items from that list.
   *
   * @deprecated
   * @param string $watchLater
   */
  public function setWatchLater($watchLater)
  {
    $this->watchLater = $watchLater;
  }
  /**
   * @deprecated
   * @return string
   */
  public function getWatchLater()
  {
    return $this->watchLater;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ChannelContentDetailsRelatedPlaylists::class, 'Google_Service_YouTube_ChannelContentDetailsRelatedPlaylists');
