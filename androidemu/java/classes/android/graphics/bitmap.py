from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.jvm.constants import *

class Bitmap_Config(metaclass=JavaClassDef, jvm_name='android/graphics/Bitmap$Config',
                    jvm_fields=[
                        JavaFieldDef('ALPHA_8', 'Landroid/graphics/Bitmap$Config;', True, object()),
                        JavaFieldDef('ARGB_4444', 'Landroid/graphics/Bitmap$Config;', True, object()),
                        JavaFieldDef('ARGB_8888', 'Landroid/graphics/Bitmap$Config;', True, object()),
                        JavaFieldDef('RGB_565', 'Landroid/graphics/Bitmap$Config;', True, object()),
                    ]):

    def __init__(self, config_name="ARGB_8888"):
        self.config_name = config_name

    def __repr__(self):
        return f"Bitmap$Config({self.config_name})"

Bitmap_Config.ALPHA_8 = Bitmap_Config("ALPHA_8")
Bitmap_Config.ARGB_4444 = Bitmap_Config("ARGB_4444")
Bitmap_Config.ARGB_8888 = Bitmap_Config("ARGB_8888")
Bitmap_Config.RGB_565 = Bitmap_Config("RGB_565")