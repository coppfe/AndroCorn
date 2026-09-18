from dataclasses import dataclass


@dataclass
class DisplayInfo:
    width: int = 1080
    height: int = 2400
    density_dpi: int = 440
    scale: float = 2.75
    refresh_rate: float = 60.0
    orientation: int = 0  # 0 = Portrait, 1 = Landscape

    def to_am_config(self, mcc: str = "250", mnc: str = "01", locale: str = "ru-rRU") -> str:
        sw_dp = int(min(self.width, self.height) / self.scale)
        w_dp = int(self.width / self.scale)
        h_dp = int(self.height / self.scale)
        return (
            f"mcc{mcc}-mnc{mnc}-{locale},ldltr,sw{sw_dp}dp,w{w_dp}dp,h{h_dp}dp,"
            f"{self.density_dpi}dpi,nokeys,notouch,keysasaccent"
        )