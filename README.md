# DrupalPasswordEncoderBundle

## Installation

To install MarkupFieldBundle with Composer just type in your terminal:

```bash
php composer.phar require mdespeuilles/markupfieldbundle
```

Now update your ``AppKernel.php`` file, and
register the new bundle:

```php
<?php

// in AppKernel::registerBundles()
$bundles = array(
    // ...
    new Mdespeuilles\MarkupFieldBundle\MdespeuillesMarkupFieldBundle(),
    // ...
);
```

## Usage
