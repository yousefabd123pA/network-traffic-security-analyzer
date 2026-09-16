# Note: Adjust the import path if your port_scan.py is not in a 'rules' folder
from rules.port_scan import PortScanRule

print()
print("=" * 65)
print(" PORT SCAN RULE TEST SUITE ".center(65, "="))
print("=" * 65)

# Initialize the rule with default thresholds
rule = PortScanRule(
    min_probes=50,
    min_rate=5.0,
    max_inter_arrival=0.2,
    sustained_seconds=3.0
)

def test_scenario(name, features):
    """Helper function to run a scenario and print formatted results."""
    print(f"\n--- Scenario: {name} ---")
    print("Input Features (from 3_tracker.py):")
    for k, v in features.items():
        print(f"  {k:<20}: {v}")
        
    # Run the detection logic
    result = rule.detect(features)
    
    print("\nDetection Result:")
    print(f"  Detected : {result['detected']}")
    print(f"  Attack   : {result['attack']}")
    print(f"  Severity : {result['severity']}")
    
    print("\nAssessment & Group Strength:")
    print(f"  Volume      : {result['assessment']['volume']:<25} [{result['group_strength']['volume']}]")
    print(f"  Intensity   : {result['assessment']['intensity']:<25} [{result['group_strength']['intensity']}]")
    print(f"  Persistence : {result['assessment']['persistence']:<25} [{result['group_strength']['persistence']}]")
    
    print(f"\n  Strong Groups: {result['strong_groups']} | Moderate Groups: {result['moderate_groups']}")
    print("-" * 65)


# =========================================
# TEST SCENARIOS
# =========================================

# 1. Normal Traffic (Should be Informational / Not Detected)
test_scenario("1. Normal Traffic (No Scan)", {
    "request_count": 10,
    "request_rate": 1.0,
    "avg_inter_arrival": 1.0,
    "sustained_duration": 1.0
})

# 2. Suspicious Activity (Should be Low Severity)
# Moderate Volume + Moderate Intensity = Low Severity
test_scenario("2. Suspicious Activity (Low Severity)", {
    "request_count": 40,        # Moderate (>= 35)
    "request_rate": 4.0,        # Moderate (>= 3.5)
    "avg_inter_arrival": 0.3,   # Weak (> 0.2)
    "sustained_duration": 1.0   # Weak (< 2.1)
})

# 3. Possible Port Scan (Should be Medium Severity)
# Strong Volume + Moderate Intensity = Medium Severity
test_scenario("3. Possible Port Scan (Medium Severity)", {
    "request_count": 60,        # Strong (>= 50)
    "request_rate": 4.0,        # Moderate (>= 3.5)
    "avg_inter_arrival": 0.3,   # Weak (> 0.2)
    "sustained_duration": 1.0   # Weak (< 2.1)
})

# 4. Confirmed Port Scan (Should be High Severity)
# Strong Volume + Strong Intensity + Strong Persistence = High Severity
test_scenario("4. Confirmed Port Scan (High Severity)", {
    "request_count": 150,       # Strong (>= 50)
    "request_rate": 15.0,       # Strong (>= 5.0)
    "avg_inter_arrival": 0.05,  # Strong (<= 0.2)
    "sustained_duration": 8.0   # Strong (>= 3.0)
})


print()
print("=" * 65)
print(" TEST COMPLETE ".center(65, "="))
print("=" * 65)
print()
