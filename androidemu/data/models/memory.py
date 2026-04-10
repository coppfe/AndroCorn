from dataclasses import dataclass

	# 	"memory": {
	# 		"ram_total_mb": 8192,
	# 		"ram_free_percent_start": 45,
	# 		"swap_total_mb": 2048
	# 	},

@dataclass
class Memory:
    ram_total_mb: int = 8192
    ram_free_percent_start: int = 45
    swap_total_mb: int = 2048