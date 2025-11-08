#CSES - City Security Evaluation System (Algorithm for Threat Detection)
import time
from typing import List, Dict, Tuple, Any

# --- CONFIGURATION ---
# Centralized configuration for easy tuning
CONFIG = {
    'PRUNE_AGE_S': 5.0,
    'PIXELS_TO_METERS': 0.1,
    'STOP_SPEED_THRESHOLD_MPS': 0.5,
    'ANOMALY_THRESHOLD': 0.7,
    'ALERT_PROBABILITY_THRESHOLD': 0.75,
}

# --- DATA STRUCTURES (as would be received from a Model API) ---
Detection = Dict[str, Any]
FrameData = Dict[str, Any] # {'timestamp': 167..., 'detections': [Detection, ...]}
TrackedObject = Dict[str, Any]

# ==============================================================================
# LAYER 2: BASELINE ANOMALY DETECTION (The "Gut Feeling")
# ==============================================================================
class BaselineModel:
    """
    Simulates a pre-trained Pattern-of-Life (PoL) model.
    In a real system, this would be a complex model (e.g., Gaussian Mixture Model)
    trained on hours of footage to learn normal traffic patterns.
    """
    def __init__(self):
        # Define "normal" areas for this simulation
        self.normal_road_polygon = [(0, 220), (1000, 220), (1000, 300), (0, 300)]
        self.normal_stopping_polygon = [(800, 220), (900, 220), (900, 300), (800, 300)] # e.g., a traffic light

    def _is_point_in_polygon(self, point: Tuple[int, int], polygon: List[Tuple[int, int]]) -> bool:
        x, y = point; n = len(polygon); inside = False
        p1x, p1y = polygon[0]
        for i in range(n + 1):
            p2x, p2y = polygon[i % n]
            if y > min(p1y, p2y) and y <= max(p1y, p2y) and x <= max(p1x, p2x):
                if p1y != p2y: xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                if p1x == p2x or x <= xinters: inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    def calculate_anomaly_score(self, track: TrackedObject, is_stopped: bool) -> float:
        """
        Returns a score from 0.0 (perfectly normal) to 1.0 (highly anomalous).
        """
        current_pos = track['history'][-1]['pos']
        
        # Location Anomaly: Is the object in a place it shouldn't be?
        location_anomaly = 0.0
        if not self._is_point_in_polygon(current_pos, self.normal_road_polygon):
            location_anomaly = 0.95

        # Behavioral Anomaly: Is the object stopped in a place it shouldn't be?
        stop_anomaly = 0.0
        if is_stopped and not self._is_point_in_polygon(current_pos, self.normal_stopping_polygon):
            stop_anomaly = 0.95

        # Return the highest anomaly score
        return max(location_anomaly, stop_anomaly)

# ==============================================================================
# LAYER 3: BEHAVIORAL ANALYSIS ENGINE (The "Brain")
# ==============================================================================
class BehavioralEngine:
    """
    Manages and matches object behavior against pre-defined threat playbooks.
    """
    def __init__(self):
        self.playbooks = self._load_playbooks()
        self.active_scenarios: Dict[int, Dict] = {} # {obj_id: {'playbook': name, 'state_index': i}}

    def _load_playbooks(self):
        # Defines known attack patterns as state machines.
        # Triggers are lambda functions that check conditions for state transition.
        return {
            "VBIED_DROPOFF": {
                'states': ['APPROACH', 'STOPPED_IN_ANOMALOUS_ZONE', 'DRIVER_EXIT', 'SEPARATION'],
                'triggers': [
                    lambda track, ctx: ctx['is_stopped'] and ctx['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD'],
                    lambda track, ctx: self._check_driver_exit(track, ctx),
                    lambda track, ctx: self._check_driver_separation(track, ctx)
                ]
            }
        }
    
    def _check_driver_exit(self, vehicle_track: TrackedObject, context: Dict) -> bool:
        """Check if a person just appeared near the stopped vehicle."""
        vehicle_pos = vehicle_track['history'][-1]['pos']
        for other_obj in context['all_tracks'].values():
            if other_obj['label'] == 'pedestrian' and len(other_obj['history']) == 1: # Newly appeared
                ped_pos = other_obj['history'][-1]['pos']
                dist = ((vehicle_pos[0] - ped_pos[0])**2 + (vehicle_pos[1] - ped_pos[1])**2)**0.5
                if dist < 50: # Person appeared within 50 pixels
                    # Link the pedestrian to the vehicle for the next state check
                    self.active_scenarios[vehicle_track['obj_id']]['linked_obj_id'] = other_obj['obj_id']
                    return True
        return False

    def _check_driver_separation(self, vehicle_track: TrackedObject, context: Dict) -> bool:
        """Check if the linked pedestrian is moving away from the vehicle."""
        if 'linked_obj_id' not in self.active_scenarios[vehicle_track['obj_id']]:
            return False
        
        ped_id = self.active_scenarios[vehicle_track['obj_id']]['linked_obj_id']
        if ped_id not in context['all_tracks'] or len(context['all_tracks'][ped_id]['history']) < 2:
            return False

        ped_track = context['all_tracks'][ped_id]
        ped_pos_curr = ped_track['history'][-1]['pos']
        ped_pos_prev = ped_track['history'][-2]['pos']
        vehicle_pos = vehicle_track['history'][-1]['pos']
        
        dist_curr = ((vehicle_pos[0] - ped_pos_curr[0])**2 + (vehicle_pos[1] - ped_pos_curr[1])**2)**0.5
        dist_prev = ((vehicle_pos[0] - ped_pos_prev[0])**2 + (vehicle_pos[1] - ped_pos_prev[1])**2)**0.5
        
        # If the person is moving and their distance from the vehicle is increasing
        if dist_curr > dist_prev and context['speeds'][ped_id] > CONFIG['STOP_SPEED_THRESHOLD_MPS']:
            return True
        return False

    def update_scenarios(self, track: TrackedObject, context: Dict):
        """Updates the state of any active playbook for the given track."""
        # Start a new scenario if the object is anomalous and not already in one
        if track['obj_id'] not in self.active_scenarios and context['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD']:
            for name, playbook in self.playbooks.items():
                if track['label'] in ['van', 'truck', 'car']: # Playbook is relevant for this object type
                    self.active_scenarios[track['obj_id']] = {'playbook': name, 'state_index': 0}
        
        # Advance the state of existing scenarios
        if track['obj_id'] in self.active_scenarios:
            scenario = self.active_scenarios[track['obj_id']]
            playbook = self.playbooks[scenario['playbook']]
            current_state_index = scenario['state_index']

            # Check if we can move to the next state
            if current_state_index < len(playbook['triggers']):
                trigger_func = playbook['triggers'][current_state_index]
                if trigger_func(track, context):
                    scenario['state_index'] += 1 # Advance state
                    print(f"DEBUG: Object {track['obj_id']} advanced to state '{playbook['states'][scenario['state_index']]}' in playbook '{scenario['playbook']}'")

    def get_matched_playbook_info(self, obj_id: int) -> Dict | None:
        """Returns the current state of a matched playbook for an object."""
        if obj_id in self.active_scenarios:
            scenario = self.active_scenarios[obj_id]
            playbook = self.playbooks[scenario['playbook']]
            state_name = playbook['states'][scenario['state_index']]
            return {'name': scenario['playbook'], 'state': state_name}
        return None

# ==============================================================================
# LAYER 4: THREAT SYNTHESIS & PRIORITIZATION (The "Commander")
# ==============================================================================
class ThreatSynthesizer:
    """
    Fuses all evidence using a probabilistic model to calculate threat likelihood.
    """
    def __init__(self):
        # P(Evidence | Threat). How much each piece of evidence multiplies our belief.
        self.likelihoods = {
            'VBIED_DROPOFF': {
                'high_anomaly': 3.0,
                'state_STOPPED_IN_ANOMALOUS_ZONE': 10.0,
                'state_DRIVER_EXIT': 50.0,
                'state_SEPARATION': 100.0,
            }
        }
        # {obj_id: {'VBIED_DROPOFF': 0.0001, ...}}
        self.threat_probabilities: Dict[int, Dict[str, float]] = {}

    def update_threat_probabilities(self, obj_id: int, evidence: Dict):
        """Updates threat probabilities for an object using new evidence."""
        if obj_id not in self.threat_probabilities:
            # Initialize with very low prior probabilities
            self.threat_probabilities[obj_id] = {'VBIED_DROPOFF': 0.0001}

        # Calculate the belief multiplier based on evidence
        multiplier = 1.0
        playbook_info = evidence.get('playbook_info')
        if playbook_info:
            threat_name = playbook_info['name']
            state_name = playbook_info['state']
            if threat_name in self.likelihoods:
                # Get multiplier for the specific state
                multiplier *= self.likelihoods[threat_name].get(f'state_{state_name}', 1.0)
        
        elif evidence['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD']:
             # Apply a smaller multiplier just for being anomalous
             multiplier *= self.likelihoods['VBIED_DROPOFF']['high_anomaly']

        # Update the probability (simplified Bayesian update)
        # P(Threat|Evidence) is proportional to P(Evidence|Threat) * P(Threat)
        for threat, prob in self.threat_probabilities[obj_id].items():
            if threat in self.likelihoods: # Only update relevant threats
                self.threat_probabilities[obj_id][threat] *= multiplier

        self._normalize(obj_id)

    def _normalize(self, obj_id: int):
        """Keeps probabilities between 0 and 1."""
        for threat, prob in self.threat_probabilities[obj_id].items():
            # A simple normalization: P(T|E) = P(T|E) / (P(T|E) + P(not T|E))
            # For simplicity here, we just cap it. A full implementation would be more complex.
            if prob > 0.999:
                self.threat_probabilities[obj_id][threat] = 0.999

    def get_prioritized_alerts(self) -> List[Dict]:
        """Gets all threats exceeding the alert threshold, sorted by probability."""
        alerts = []
        for obj_id, threats in self.threat_probabilities.items():
            for threat, probability in threats.items():
                if probability > CONFIG['ALERT_PROBABILITY_THRESHOLD']:
                    alerts.append({
                        'obj_id': obj_id,
                        'threat_type': threat,
                        'probability': probability,
                    })
        return sorted(alerts, key=lambda x: x['probability'], reverse=True)

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
class ThreatDetector:
    """
    The main class that orchestrates all layers of the threat detection process.
    """
    def __init__(self):
        self.tracked_objects: Dict[int, TrackedObject] = {}
        self.baseline_model = BaselineModel()
        self.behavioral_engine = BehavioralEngine()
        self.threat_synthesizer = ThreatSynthesizer()
        
    def _get_center(self, bbox: Tuple[int, int, int, int]) -> Tuple[int, int]:
        x, y, w, h = bbox
        return (x + w // 2, y + h // 2)

    def _update_tracks(self, detections: List[Detection], current_time: float):
        # Simplified tracker: assumes IDs are consistent from an external tracker
        for det in detections:
            obj_id = det['obj_id']
            center_pos = self._get_center(det['bbox'])
            if obj_id not in self.tracked_objects:
                self.tracked_objects[obj_id] = {'obj_id': obj_id, 'label': det['label'], 'history': []}
            self.tracked_objects[obj_id]['history'].append({'pos': center_pos, 'time': current_time})
            self.tracked_objects[obj_id]['last_updated'] = current_time

    def _calculate_speed_mps(self, track: TrackedObject) -> float:
        if len(track['history']) < 2: return 0.0
        p1 = track['history'][-2]; p2 = track['history'][-1]
        dist_m = (((p2['pos'][0] - p1['pos'][0])**2 + (p2['pos'][1] - p1['pos'][1])**2)**0.5) * CONFIG['PIXELS_TO_METERS']
        time_s = p2['time'] - p1['time']
        return dist_m / time_s if time_s > 0 else 0.0

    def process_frame_data(self, frame_data: FrameData) -> List[Dict]:
        """
        Main processing loop that mimics consuming from a model API.
        """
        current_time = frame_data['timestamp']
        self._update_tracks(frame_data['detections'], current_time)

        # Build context for the current frame
        context = {
            'all_tracks': self.tracked_objects,
            'speeds': {obj_id: self._calculate_speed_mps(t) for obj_id, t in self.tracked_objects.items()}
        }

        # Process each object through the layers
        for obj_id, track in self.tracked_objects.items():
            is_stopped = context['speeds'][obj_id] < CONFIG['STOP_SPEED_THRESHOLD_MPS']
            
            # Layer 2: Get anomaly score
            anomaly_score = self.baseline_model.calculate_anomaly_score(track, is_stopped)
            
            # Layer 3: Update behavioral playbooks
            context['anomaly_score'] = anomaly_score
            context['is_stopped'] = is_stopped
            self.behavioral_engine.update_scenarios(track, context)
            
            # Layer 4: Synthesize evidence and update threat probabilities
            playbook_info = self.behavioral_engine.get_matched_playbook_info(obj_id)
            evidence = {'anomaly_score': anomaly_score, 'playbook_info': playbook_info}
            self.threat_synthesizer.update_threat_probabilities(obj_id, evidence)

        # Return final, prioritized alerts
        return self.threat_synthesizer.get_prioritized_alerts()

# ==============================================================================
# SIMULATION
# ==============================================================================
if __name__ == "__main__":
    detector = ThreatDetector()

    # A van (101) drives, stops anomalously, a person (202) exits and separates.
    simulation_api_feed = [
        {'timestamp': 1.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (100, 240, 60, 50)}]},
        {'timestamp': 2.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (250, 245, 60, 50)}]},
        # Van stops in an ANOMALOUS location (not in the normal road polygon)
        {'timestamp': 3.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)}]},
        {'timestamp': 4.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)}]},
        # A person appears next to the van. This triggers the DRIVER_EXIT state.
        {'timestamp': 5.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (450, 350, 20, 40)}
        ]},
        # The person walks away from the van. This triggers the SEPARATION state.
        {'timestamp': 6.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (480, 355, 20, 40)}
        ]},
        {'timestamp': 7.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (510, 360, 20, 40)}
        ]},
    ]
    
    print("--- Military-Grade Threat Detection Simulation ---")
    for frame_data in simulation_api_feed:
        print(f"\n--- Processing Frame at Time: {frame_data['timestamp']:.1f}s ---")
        alerts = detector.process_frame_data(frame_data)

        # Log the status of the primary object of interest
        if 101 in detector.threat_synthesizer.threat_probabilities:
            prob = detector.threat_synthesizer.threat_probabilities[101]['VBIED_DROPOFF']
            playbook_info = detector.behavioral_engine.get_matched_playbook_info(101)
            state = playbook_info['state'] if playbook_info else "N/A"
            print(f"  Van (ID 101) Status | Playbook State: {state} | VBIED Probability: {prob:.6f}")

        if alerts:
            print("\n  !!! ACTIONABLE THREAT DETECTED !!!")
            for alert in alerts:
                print(f"  > ALERT: Object ID {alert['obj_id']} is a possible {alert['threat_type']}.")
                print(f"    CONFIDENCE: {alert['probability']:.1%}")
                print(f"    ACTION: IMMEDIATE INVESTIGATION REQUIRED.")
        
        time.sleep(1.5)

