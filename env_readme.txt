There are two environment variables you will need to set when
testing this code:

BOTO_CONFIG  - Set this to the path to the boto.cfg file.
               This could be as simple as "./boto.cfg", and isn't needed
               at all if you've copied it to one of the standard locations
               such as "/etc/boto.cfg" or "~/.boto".

PYTHONPATH   - Make sure this includes the path to the Halo Python library
               and to the AWS wrapper code. This could be as simple as:
               ../Halo:../AwsToHalo
