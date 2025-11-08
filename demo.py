#CSES - City Security Evaluation System (Algorithm for Threat Detection)
import time
from typing import List, Dict, Tuple, Any

# --- CONFIGURATION ---
CONFIG = {
    'PRUNE_AGE_S': 5.0,
    'PIXELS_TO_METERS': 0.1,
    'STOP_SPEED_THRESHOLD_MPS': 0.5,
    'ANOMALY_THRESHOLD': 0.7,
    'ALERT_PROBABILITY_THRESHOLD': 0.75,
}

# --- DATA STRUCTURES (as would be received from a Model API) ---
Detection = Dict[str, Any]
FrameData = Dict[str, Any]
TrackedObject = Dict[str, Any]

# ==============================================================================
# LAYER 2: BASELINE ANOMALY DETECTION (The "Gut Feeling")
# ==============================================================================
class BaselineModel:
    """Simulates a pre-trained Pattern-of-Life (PoL) model."""
    def __init__(self):
        self.normal_road_polygon = [(0, 220), (1000, 220), (1000, 300), (0, 300)]
        self.normal_stopping_polygon = [(800, 220), (900, 220), (900, 300), (800, 300)]

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
        current_pos = track['history'][-1]['pos']
        location_anomaly = 0.0
        if not self._is_point_in_polygon(current_pos, self.normal_road_polygon):
            location_anomaly = 0.95
        stop_anomaly = 0.0
        if is_stopped and not self._is_point_in_polygon(current_pos, self.normal_stopping_polygon):
            stop_anomaly = 0.95
        return max(location_anomaly, stop_anomaly)

# ==============================================================================
# LAYER 3: BEHAVIORAL ANALYSIS ENGINE (The "Brain")
# ==============================================================================
class BehavioralEngine:
    """Manages and matches object behavior against pre-defined threat playbooks."""
    def __init__(self):
        self.playbooks = self._load_playbooks()
        self.active_scenarios: Dict[int, Dict] = {}

    def _load_playbooks(self):
        # FINAL FIX: The 'states' and 'triggers' lists are now perfectly aligned.
        # 'triggers[0]' now correctly corresponds to 'states[0]'.
        return {
            "VBIED_DROPOFF": {
                'states': ['STOPPED_IN_ANOMALOUS_ZONE', 'DRIVER_EXIT', 'SEPARATION'],
                'triggers': [
                    lambda track, ctx: len(track['history']) > 1 and ctx['is_stopped'] and ctx['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD'],
                    lambda track, ctx: self._check_driver_exit(track, ctx),
                    lambda track, ctx: self._check_driver_separation(track, ctx)
                ]
            }
        }
    
    def _check_driver_exit(self, vehicle_track: TrackedObject, context: Dict) -> bool:
        vehicle_pos = vehicle_track['history'][-1]['pos']
        for other_obj in context['all_tracks'].values():
            if other_obj['label'] == 'pedestrian' and len(other_obj['history']) == 1:
                ped_pos = other_obj['history'][-1]['pos']
                dist = ((vehicle_pos[0] - ped_pos[0])**2 + (vehicle_pos[1] - ped_pos[1])**2)**0.5
                if dist < 50:
                    self.active_scenarios[vehicle_track['obj_id']]['linked_obj_id'] = other_obj['obj_id']
                    return True
        return False

    def _check_driver_separation(self, vehicle_track: TrackedObject, context: Dict) -> bool:
        if 'linked_obj_id' not in self.active_scenarios.get(vehicle_track['obj_id'], {}): return False
        ped_id = self.active_scenarios[vehicle_track['obj_id']]['linked_obj_id']
        if ped_id not in context['all_tracks'] or len(context['all_tracks'][ped_id]['history']) < 2: return False
        ped_track = context['all_tracks'][ped_id]
        ped_pos_curr = ped_track['history'][-1]['pos']; ped_pos_prev = ped_track['history'][-2]['pos']
        vehicle_pos = vehicle_track['history'][-1]['pos']
        dist_curr = ((vehicle_pos[0] - ped_pos_curr[0])**2 + (vehicle_pos[1] - ped_pos_curr[1])**2)**0.5
        dist_prev = ((vehicle_pos[0] - ped_pos_prev[0])**2 + (vehicle_pos[1] - ped_pos_prev[1])**2)**0.5
        if dist_curr > dist_prev and context['speeds'][ped_id] > CONFIG['STOP_SPEED_THRESHOLD_MPS']: return True
        return False

    def update_scenarios(self, track: TrackedObject, context: Dict) -> bool:
        """Updates playbook states and returns True if a state has just changed."""
        state_just_changed = False
        if track['obj_id'] not in self.active_scenarios and context['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD']:
            if track['label'] in ['van', 'truck', 'car']:
                self.active_scenarios[track['obj_id']] = {'playbook': "VBIED_DROPOFF", 'state_index': -1}

        if track['obj_id'] in self.active_scenarios:
            scenario = self.active_scenarios[track['obj_id']]
            playbook = self.playbooks[scenario['playbook']]
            current_state_index = scenario['state_index']
            next_state_index = current_state_index + 1

            if next_state_index < len(playbook['triggers']):
                trigger_func = playbook['triggers'][next_state_index]
                if trigger_func(track, context):
                    scenario['state_index'] += 1
                    state_just_changed = True
                    new_state = playbook['states'][scenario['state_index']]
                    print(f"DEBUG: Object {track['obj_id']} advanced to state '{new_state}' in playbook '{scenario['playbook']}'")
        
        return state_just_changed

    def get_matched_playbook_info(self, obj_id: int) -> Dict | None:
        if obj_id in self.active_scenarios:
            scenario = self.active_scenarios[obj_id]
            if scenario['state_index'] >= 0:
                playbook = self.playbooks[scenario['playbook']]
                state_name = playbook['states'][scenario['state_index']]
                return {'name': scenario['playbook'], 'state': state_name}
        return None

# ==============================================================================
# LAYER 4: THREAT SYNTHESIS & PRIORITIZATION (The "Commander")
# ==============================================================================
class ThreatSynthesizer:
    """Fuses all evidence using a probabilistic model to calculate threat likelihood."""
    def __init__(self):
        self.likelihoods = {
            'VBIED_DROPOFF': {
                'state_STOPPED_IN_ANOMALOUS_ZONE': 10.0,
                'state_DRIVER_EXIT': 50.0,
                'state_SEPARATION': 100.0,
            }
        }
        self.threat_probabilities: Dict[int, Dict[str, float]] = {}

    def update_threat_probabilities(self, obj_id: int, evidence: Dict):
        if obj_id not in self.threat_probabilities:
            self.threat_probabilities[obj_id] = {'VBIED_DROPOFF': 0.0001}

        playbook_info = evidence.get('playbook_info')
        state_just_changed = evidence.get('state_just_changed', False)
        
        multiplier = 1.0
        if playbook_info and state_just_changed:
            threat_name = playbook_info['name']
            state_name = playbook_info['state']
            if threat_name in self.likelihoods:
                multiplier = self.likelihoods[threat_name].get(f'state_{state_name}', 1.0)
        elif evidence['anomaly_score'] > CONFIG['ANOMALY_THRESHOLD']:
            multiplier = 1.05

        if multiplier > 1.0:
            for threat in self.threat_probabilities[obj_id]:
                 self.threat_probabilities[obj_id][threat] *= multiplier
        
        self._normalize(obj_id)

    def _normalize(self, obj_id: int):
        for threat, prob in self.threat_probabilities[obj_id].items():
            if prob > 0.999:
                self.threat_probabilities[obj_id][threat] = 0.999

    def get_prioritized_alerts(self) -> List[Dict]:
        alerts = []
        for obj_id, threats in self.threat_probabilities.items():
            for threat, probability in threats.items():
                if probability > CONFIG['ALERT_PROBABILITY_THRESHOLD']:
                    alerts.append({'obj_id': obj_id, 'threat_type': threat, 'probability': probability})
        return sorted(alerts, key=lambda x: x['probability'], reverse=True)

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
class ThreatDetector:
    """The main class that orchestrates all layers of the threat detection process."""
    def __init__(self):
        self.tracked_objects: Dict[int, TrackedObject] = {}
        self.baseline_model = BaselineModel()
        self.behavioral_engine = BehavioralEngine()
        self.threat_synthesizer = ThreatSynthesizer()
        
    def _get_center(self, bbox: Tuple[int, int, int, int]) -> Tuple[int, int]:
        x, y, w, h = bbox; return (x + w // 2, y + h // 2)

    def _update_tracks(self, detections: List[Detection], current_time: float):
        for det in detections:
            obj_id = det['obj_id']
            center_pos = self._get_center(det['bbox'])
            if obj_id not in self.tracked_objects:
                self.tracked_objects[obj_id] = {'obj_id': obj_id, 'label': det['label'], 'history': []}
            self.tracked_objects[obj_id]['history'].append({'pos': center_pos, 'time': current_time})
            self.tracked_objects[obj_id]['last_updated'] = current_time

    def _calculate_speed_mps(self, track: TrackedObject) -> float:
        if len(track['history']) < 2: return 0.0
        p1=track['history'][-2]; p2=track['history'][-1]
        dist_m = (((p2['pos'][0]-p1['pos'][0])**2 + (p2['pos'][1]-p1['pos'][1])**2)**0.5) * CONFIG['PIXELS_TO_METERS']
        time_s = p2['time']-p1['time']
        return dist_m/time_s if time_s > 0 else 0.0

    def process_frame_data(self, frame_data: FrameData) -> List[Dict]:
        current_time = frame_data['timestamp']
        self._update_tracks(frame_data['detections'], current_time)

        context = {
            'all_tracks': self.tracked_objects,
            'speeds': {obj_id: self._calculate_speed_mps(t) for obj_id, t in self.tracked_objects.items()}
        }

        for obj_id, track in self.tracked_objects.items():
            is_stopped = context['speeds'][obj_id] < CONFIG['STOP_SPEED_THRESHOLD_MPS']
            anomaly_score = self.baseline_model.calculate_anomaly_score(track, is_stopped)
            context['anomaly_score'] = anomaly_score
            context['is_stopped'] = is_stopped
            
            state_just_changed = self.behavioral_engine.update_scenarios(track, context)
            playbook_info = self.behavioral_engine.get_matched_playbook_info(obj_id)
            evidence = {'anomaly_score': anomaly_score, 'playbook_info': playbook_info, 'state_just_changed': state_just_changed}
            self.threat_synthesizer.update_threat_probabilities(obj_id, evidence)

        return self.threat_synthesizer.get_prioritized_alerts()

# ==============================================================================
# SIMULATION
# ==============================================================================
if __name__ == "__main__":
    detector = ThreatDetector()

    simulation_api_feed = [
        {'timestamp': 1.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (100, 240, 60, 50)}]},
        {'timestamp': 2.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (250, 245, 60, 50)}]},
        {'timestamp': 3.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)}]},
        {'timestamp': 4.0, 'detections': [{'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)}]},
        {'timestamp': 5.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (450, 350, 20, 40)}
        ]},
        {'timestamp': 6.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (480, 355, 20, 40)}
        ]},
        {'timestamp': 7.0, 'detections': [
            {'obj_id': 101, 'label': 'van', 'bbox': (400, 350, 60, 50)},
            {'obj_id': 202, 'label': 'pedestrian', 'bbox': (510, 360, 20, 40)}
        ]},
    ]
    
    print("--- Military-Grade Threat Detection Simulation (FINAL) ---")
    for frame_data in simulation_api_feed:
        print(f"\n--- Processing Frame at Time: {frame_data['timestamp']:.1f}s ---")
        alerts = detector.process_frame_data(frame_data)

        if 101 in detector.threat_synthesizer.threat_probabilities:
            prob = detector.threat_synthesizer.threat_probabilities[101]['VBIED_DROPOFF']
            playbook_info = detector.behavioral_engine.get_matched_playbook_info(101)
            # FINAL FIX: Correctly display "APPROACH" as the default state before a playbook is triggered.
            state = playbook_info['state'] if playbook_info else "APPROACH"
            print(f"  Van (ID 101) Status | Playbook State: {state} | VBIED Probability: {prob:.6f}")

        if alerts:
            print("\n  !!! ACTIONABLE THREAT DETECTED !!!")
            for alert in alerts:
                print(f"  > ALERT: Object ID {alert['obj_id']} is a possible {alert['threat_type']}.")
                print(f"    CONFIDENCE: {alert['probability']:.1%}")
                print(f"    ACTION: IMMEDIATE INVESTIGATION REQUIRED.")
        
        time.sleep(1.0)

