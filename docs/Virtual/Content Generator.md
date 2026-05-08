Here is too much code and comment every func maybe not needed. I just show you how it works.

This class is using for generating content and check is current file is virtual just by checking local regular exp.

You can check how it works just by clicking arrow below.

Maybe, it's not the best implement variant, but...

**using only for device files**
<small>probably for any file can be</small>

::: androidemu.utils.generators.vfs_content.ContentGenerator
    options:
      filters: ["!^_"]
      show_root_heading: true