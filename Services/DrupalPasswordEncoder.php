<?php
namespace Mdespeuilles\DrupalPasswordEncoderBundle\Services;

use Mdespeuilles\DrupalPasswordEncoderBundle\Services\Password\PhpassHashedPassword;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;

class DrupalPasswordEncoder implements PasswordEncoderInterface
{
    const DRUPAL_HASH_COUNT = 15;
    
    /**
     * @var \Mdespeuilles\DrupalPasswordEncoderBundle\Services\Password\PhpassHashedPassword
     */
    protected $drupalPasswordService;
    
    /**
     * DrupalPasswordEncoder constructor.
     */
    public function __construct()
    {
        $this->drupalPasswordService = new PhpassHashedPassword(self::DRUPAL_HASH_COUNT);
    }
    
    /**
     * Encode a password to a Drupal way
     *
     * @param string $password
     * @param string $salt
     * @return string
     */
    public function encodePassword($password, $salt)
    {
        return $this->drupalPasswordService->hash($password);
    }
    
    /**
     * Check if password is valid
     *
     * @param string $encoded
     * @param string $raw
     * @param string $salt
     * @return bool
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        return $this->drupalPasswordService->check($raw, $encoded);
    }
}
