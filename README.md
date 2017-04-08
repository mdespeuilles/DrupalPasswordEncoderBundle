# DrupalPasswordEncoderBundle

This bundle provide just a Drupal password encoder for Symfony 2/3.
It will be very usefull if you want migrate an old Drupal 7 or 8 site to Symfony
and keep the users password.

## Installation

To install DrupalPasswordEncoderBundle with Composer just type in your terminal:

```bash
php composer.phar require mdespeuilles/drupalpasswordencoderbundle
```

Now update your ``AppKernel.php`` file, and
register the new bundle:

```php
<?php

// in AppKernel::registerBundles()
$bundles = array(
    // ...
    new Mdespeuilles\DrupalPasswordEncoderBundle\MdespeuillesDrupalPasswordEncoderBundle(),
    // ...
);
```

## Usage

In your security.yml change the default encoders :

```yml

security:
    encoders:
        AppBundle\Entity\User:
            id: mdespeuilles_drupal_password_encoder
            
    ...

```
