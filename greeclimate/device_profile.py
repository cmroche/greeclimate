"""Match firmware quirks by firmware code, independent of module and version."""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class DeviceProfile:
    firmware_code: str
    temperature_offset: Optional[int] = None
    relearn_temperature_offset: bool = False
    buzzer_properties: Optional[Tuple[str, ...]] = None
    cooling_mode_value: Optional[int] = None
    capabilities: Tuple[Tuple[str, str, bool], ...] = ()


# See docs/HIDS.md for code-scope policy and calibration limitations.
KNOWN_PROFILES: Tuple[DeviceProfile, ...] = (
    DeviceProfile("362001000748", 40),
    DeviceProfile("362001000762", 40, buzzer_properties=()),
    DeviceProfile(
        "362001000835", 0, buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "steady_heat", False),
            ("dehumidifier", "current_humidity", False),
        ),
    ),
    DeviceProfile("362001000968", 0),
    DeviceProfile("362001003795", 40, buzzer_properties=()),
    DeviceProfile(
        "362001060200", 0, buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "steady_heat", False),
            ("dehumidifier", "current_humidity", False),
        ),
    ),
    DeviceProfile(
        "362001060297", 0, buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "steady_heat", False),
            ("dehumidifier", "current_humidity", False),
        ),
    ),
    DeviceProfile(
        "362001060498", 0, buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "steady_heat", False),
            ("dehumidifier", "current_humidity", False),
        ),
    ),
    DeviceProfile(
        "362001060499", 0, buzzer_properties=("Buzzer_ON_OFF",),
        capabilities=(("dehumidifier", "current_humidity", False),),
    ),
    DeviceProfile("362001060990", 40, buzzer_properties=()),
    DeviceProfile("362001060991", 40, buzzer_properties=()),
    DeviceProfile("362001061023", 40, buzzer_properties=()),
    DeviceProfile("362001061060", 40),
    DeviceProfile("362001061111", 40, buzzer_properties=()),
    DeviceProfile("362001061234", 40),
    DeviceProfile("362001061359", 40),
    DeviceProfile("362001061380", 0),
    DeviceProfile("362001061381", 40, relearn_temperature_offset=True),
    DeviceProfile("362001061383", 40, relearn_temperature_offset=True, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001061462", 40, buzzer_properties=()),
    DeviceProfile("362001061665", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001062025", 40, buzzer_properties=()),
    DeviceProfile("362001062107", 40, buzzer_properties=()),
    DeviceProfile("362001062214", 40, buzzer_properties=()),
    DeviceProfile("362001062293", 40),
    DeviceProfile("362001062295", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001062557", 40, relearn_temperature_offset=True, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001062637", 40),
    DeviceProfile("362001062842", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001063525", 40),
    DeviceProfile("362001063794", 40, buzzer_properties=()),
    DeviceProfile("362001063903", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001063967", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001064270", 40, relearn_temperature_offset=True),
    DeviceProfile("362001064304", 40, buzzer_properties=()),
    DeviceProfile("362001064973", 40, relearn_temperature_offset=True, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001065016", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001065029", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001065130", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001065279", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001065280", 40),
    DeviceProfile("362001065517", 40),
    DeviceProfile("362001065602", 0),
    DeviceProfile("362001065701", 40),
    DeviceProfile("362001065734", 40, buzzer_properties=()),
    DeviceProfile("362001065735", 40, buzzer_properties=()),
    DeviceProfile("362001065736", 40, buzzer_properties=()),
    DeviceProfile("362001066140", 40),
    DeviceProfile("362001066300", 40),
    DeviceProfile("362001066308", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001066326"),
    DeviceProfile("362001066380"),
    DeviceProfile("362001066511", 40),
    DeviceProfile(
        "362001066763", buzzer_properties=(), cooling_mode_value=5,
        capabilities=(
            ("air_to_water", "inlet_water_temperature_c", True),
            ("air_to_water", "outlet_water_temperature_c", True),
            ("air_to_water", "room_temperature_c", True),
            ("air_to_water", "tank_temperature_c", True),
        ),
    ),  # Sinclair SMH-100IRB / SMH-60IRB
    DeviceProfile("362001066962", 40),
    DeviceProfile("362001067419", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001067422", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001067427", 40),
    DeviceProfile("362001067540", 40),
    DeviceProfile("362001067541", 40),
    DeviceProfile("362001067928", 40),
    DeviceProfile("362001068254", 40),
    DeviceProfile("362001068295", 40),
    DeviceProfile("362001068411", 40),
    DeviceProfile("362001068458", 40, buzzer_properties=("Buzzer_ON_OFF",)),
    DeviceProfile("362001071519", 40),
    DeviceProfile(
        "362001063384", buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "current_temperature", False),
            ("air_conditioner", "anion", False),
            ("air_conditioner", "light", False),
            ("air_conditioner", "steady_heat", False),
        ),
    ),
    DeviceProfile(
        "362001067592", buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "current_temperature", False),
            ("air_conditioner", "anion", False),
            ("air_conditioner", "light", False),
            ("air_conditioner", "steady_heat", False),
        ),
    ),
    DeviceProfile(
        "362001062617",
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile(
        "362001061433", buzzer_properties=(),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile(
        "362001067012", buzzer_properties=(),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile(
        "362001065634", buzzer_properties=("Buzzer_ON_OFF",),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile(
        "362001069999",
        capabilities=(
            ("air_to_water", "power", False),
            ("air_to_water", "mode", False),
            ("air_to_water", "temperature_units", False),
            ("air_to_water", "inlet_water_temperature_c", False),
            ("air_to_water", "outlet_water_temperature_c", False),
            ("air_to_water", "room_temperature_c", False),
            ("air_to_water", "tank_temperature_c", False),
            ("air_to_water", "heating_room_target_temperature_c", False),
            ("air_to_water", "cooling_room_target_temperature_c", False),
            ("air_to_water", "heating_water_target_temperature_c", False),
            ("air_to_water", "cooling_water_target_temperature_c", False),
            ("air_to_water", "tank_target_temperature_c", False),
        ),
    ),
    DeviceProfile("362001060368", buzzer_properties=()),
    DeviceProfile(
        "362001060429", buzzer_properties=(),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile("362001060965", buzzer_properties=()),
    DeviceProfile("362001061114", buzzer_properties=()),
    DeviceProfile("362001061147", buzzer_properties=()),
    DeviceProfile("362001061272", buzzer_properties=()),
    DeviceProfile(
        "362001061608", buzzer_properties=(),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile("362001067139", buzzer_properties=()),
    DeviceProfile(
        "362001067524", buzzer_properties=(),
        capabilities=(("air_conditioner", "current_temperature", False),),
    ),
    DeviceProfile("362001060956", buzzer_properties=()),
    DeviceProfile("362001061144", buzzer_properties=()),
    DeviceProfile("362001061167", buzzer_properties=()),
    DeviceProfile("362001061824", buzzer_properties=()),
    DeviceProfile("362001062097", buzzer_properties=()),
    DeviceProfile("362001060629", buzzer_properties=()),
    DeviceProfile("362001060709", buzzer_properties=()),
    DeviceProfile("362001061068", buzzer_properties=()),
    DeviceProfile("362001061133", buzzer_properties=()),
    DeviceProfile("362001061148", buzzer_properties=()),
    DeviceProfile("362001061437", buzzer_properties=()),
    DeviceProfile(
        "362001061649", buzzer_properties=(),
        capabilities=(
            ("air_conditioner", "target_temperature", False),
            ("air_conditioner", "temperature_units", False),
            ("air_conditioner", "current_temperature", False),
            ("air_conditioner", "sleep", False),
            ("air_conditioner", "light", False),
            ("air_conditioner", "turbo", False),
            ("air_conditioner", "vertical_swing", False),
            ("dehumidifier", "target_humidity", False),
            ("dehumidifier", "dehumidifier_mode", False),
            ("dehumidifier", "current_humidity", False),
            ("dehumidifier", "clean_filter", False),
            ("dehumidifier", "water_full", False),
            ("dehumidifier", "current_temperature", False),
            ("dehumidifier", "temperature_units", False),
            ("dehumidifier", "light", False),
            ("dehumidifier", "vertical_swing", False),
        ),
    ),
    DeviceProfile("362001062071", buzzer_properties=()),
)


def match_device_profile(hid: Optional[str]) -> Optional[DeviceProfile]:
    """Match a bare firmware code or the code prefix of a reported HID."""
    if not isinstance(hid, str):
        return None
    code = hid.partition("+")[0]
    for profile in KNOWN_PROFILES:
        if profile.firmware_code == code:
            return profile
    return None
