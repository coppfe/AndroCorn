from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from androidemu.java.jvm.constants import *

TO_MILLIS_FACTORS = {
    "NANOSECONDS": 0.000001,
    "MICROSECONDS": 0.001,
    "MILLISECONDS": 1.0,
    "SECONDS": 1000.0,
    "MINUTES": 60000.0,
    "HOURS": 3600000.0,
    "DAYS": 86400000.0
}

class TimeUnit(metaclass=JavaClassDef, jvm_name='java/util/concurrent/TimeUnit',
               jvm_fields=[
                   JavaFieldDef('NANOSECONDS', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('MICROSECONDS', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('MILLISECONDS', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('SECONDS', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('MINUTES', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('HOURS', 'Ljava/util/concurrent/TimeUnit;', True, object()),
                   JavaFieldDef('DAYS', 'Ljava/util/concurrent/TimeUnit;', True, object())
               ]):

    def __init__(self, unit_name="SECONDS"):
        self.unit_name = unit_name

    @java_method_def(name='toMillis', args_list=["jlong"], signature='(J)J', native=False)
    def toMillis(self, emu, duration):
        factor = TO_MILLIS_FACTORS.get(self.unit_name, 1000.0)
        return int(duration * factor)

    @java_method_def(name='convert', args_list=["jlong", "jobject"], signature='(JLjava/util/concurrent/TimeUnit;)J', native=False)
    def convert(self, emu, duration, source_unit):
        source_factor = TO_MILLIS_FACTORS.get(source_unit.unit_name, 1000.0)
        target_factor = TO_MILLIS_FACTORS.get(self.unit_name, 1000.0)
        millis = duration * source_factor
        return int(millis / target_factor)

TimeUnit.NANOSECONDS = TimeUnit("NANOSECONDS")
TimeUnit.MICROSECONDS = TimeUnit("MICROSECONDS")
TimeUnit.MILLISECONDS = TimeUnit("MILLISECONDS")
TimeUnit.SECONDS = TimeUnit("SECONDS")
TimeUnit.MINUTES = TimeUnit("MINUTES")
TimeUnit.HOURS = TimeUnit("HOURS")
TimeUnit.DAYS = TimeUnit("DAYS")