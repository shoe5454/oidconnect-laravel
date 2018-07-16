<?php
/**
 * Created by PhpStorm.
 * User: i
 * Date: 2018/7/16
 * Time: 10:29
 */

namespace Furdarius\OIDConnect;

use Laravel\Socialite\Two\User as BaseUser;

class User extends BaseUser
{
    public $role;

    public function getRole(){
        return $this->role;
    }
}
