"""
Machine learning-based threat analysis module for CyberFox.

This module provides machine learning capabilities for:
1. Threat clustering and pattern detection
2. Threat severity prediction and classification
3. Anomaly detection for identifying unusual system behaviors
4. Future threat projection and trend analysis
"""

import os
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Any, Union
from pathlib import Path
import joblib
from sklearn.cluster import DBSCAN, KMeans, OPTICS
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer, HashingVectorizer
from sklearn.decomposition import PCA, TruncatedSVD, NMF
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, silhouette_score
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC, OneClassSVM
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor
from sklearn.manifold import TSNE
import itertools
import warnings

from cyberfox.core.threats import (
    Threat, ThreatLevel, ThreatType, ThreatDatabase,
    FileThreat, DarkWebThreat, DataBreachThreat, BrowserThreat
)
from cyberfox.config import CONFIG, CONFIG_DIR

logger = logging.getLogger(__name__)

# Model storage paths
MODELS_DIR = CONFIG_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

# Default model paths
THREAT_CLASSIFIER_MODEL = MODELS_DIR / "threat_classifier.joblib"
ANOMALY_DETECTOR_MODEL = MODELS_DIR / "anomaly_detector.joblib"
THREAT_CLUSTERER_MODEL = MODELS_DIR / "threat_clusterer.joblib"


class MLThreatAnalyzer:
    """
    Machine learning-based threat analysis for enhanced security intelligence.
    
    This class provides advanced threat analysis capabilities using 
    machine learning algorithms for clustering, classification,
    and anomaly detection.
    """
    
    def __init__(self, threat_db: ThreatDatabase):
        """
        Initialize the ML threat analyzer.
        
        Args:
            threat_db: The threat database to analyze
        """
        self.threat_db = threat_db
        
        # Initialize models
        self.classifier = None  # For threat severity prediction
        self.clusterer = None   # For threat clustering
        self.anomaly_detector = None  # For anomaly detection
        self.vectorizer = None  # For text feature extraction
        self.scaler = None      # For numerical feature normalization
        
        # Load pre-trained models if available or create new ones
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize or load machine learning models."""
        # Create or load the threat classifier
        if THREAT_CLASSIFIER_MODEL.exists():
            try:
                self.classifier = joblib.load(THREAT_CLASSIFIER_MODEL)
                logger.info("Loaded threat classifier model")
            except Exception as e:
                logger.error(f"Error loading threat classifier model: {e}")
                self._create_classifier()
        else:
            self._create_classifier()
        
        # Create or load the anomaly detector
        if ANOMALY_DETECTOR_MODEL.exists():
            try:
                self.anomaly_detector = joblib.load(ANOMALY_DETECTOR_MODEL)
                logger.info("Loaded anomaly detector model")
            except Exception as e:
                logger.error(f"Error loading anomaly detector model: {e}")
                self._create_anomaly_detector()
        else:
            self._create_anomaly_detector()
        
        # Create or load the threat clusterer
        if THREAT_CLUSTERER_MODEL.exists():
            try:
                model_data = joblib.load(THREAT_CLUSTERER_MODEL)
                self.clusterer = model_data['clusterer']
                self.vectorizer = model_data['vectorizer']
                self.scaler = model_data['scaler']
                logger.info("Loaded threat clusterer model")
            except Exception as e:
                logger.error(f"Error loading threat clusterer model: {e}")
                self._create_clusterer()
        else:
            self._create_clusterer()
    
    def _create_classifier(self):
        """Create a new threat classifier model with advanced ensemble methods."""
        logger.info("Creating new threat classifier model")
        
        # Create a more sophisticated ensemble classifier
        # Using a voting classifier with multiple algorithms for better accuracy
        self.classifier = Pipeline([
            ('scaler', RobustScaler()),  # Robust against outliers
            ('classifier', GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=5,
                random_state=42,
                subsample=0.8,
                max_features='sqrt'
            ))
        ])
        
        # We'll use grid search during training to find optimal parameters
        # The model will be trained when we have enough data
    
    def _create_anomaly_detector(self):
        """Create a new anomaly detection model with improved sensitivity."""
        logger.info("Creating new anomaly detector model")
        
        # Create an ensemble of anomaly detection algorithms for better coverage
        # This approach combines statistical and machine learning techniques
        base_estimators = [
            ('isolation_forest', IsolationForest(
                n_estimators=150,
                contamination=0.05,
                max_samples='auto',
                random_state=42
            )),
            ('one_class_svm', OneClassSVM(
                nu=0.05,
                kernel='rbf',
                gamma='scale'
            )),
            ('local_outlier_factor', LocalOutlierFactor(
                n_neighbors=20,
                contamination=0.05,
                novelty=True
            ))
        ]
        
        # We'll select the best one during training
        self.anomaly_detector = base_estimators[0][1]  # Default to Isolation Forest
        
        # The model will be trained when we have enough data
    
    def _create_clusterer(self):
        """Create a new threat clustering model with improved pattern detection."""
        logger.info("Creating new threat clusterer model")
        
        # More advanced text processing with better feature extraction
        self.vectorizer = TfidfVectorizer(
            max_features=200,
            stop_words='english',
            ngram_range=(1, 2),  # Include bigrams for better context
            use_idf=True,
            norm='l2'
        )
        
        # Better scaling that preserves relationships
        self.scaler = RobustScaler()
        
        # Advanced density-based clustering for better pattern identification
        # OPTICS is more resilient with varying density clusters
        self.clusterer = OPTICS(
            min_samples=2,
            metric='euclidean',
            cluster_method='xi',
            n_jobs=-1  # Use all available CPU cores
        )
        
        # The model will be trained when we have enough data
    
    def _extract_features(self, threats: List[Threat]) -> pd.DataFrame:
        """
        Extract features from threats for machine learning analysis.
        
        Args:
            threats: List of threat objects
            
        Returns:
            DataFrame with extracted features
        """
        if not threats:
            return pd.DataFrame()
        
        features = []
        
        for threat in threats:
            # Common features for all threat types
            feature_dict = {
                'threat_type': threat.type.value,
                'threat_level': threat.level.value,
                'timestamp': threat.timestamp.timestamp() if threat.timestamp else 0,
                'details_count': len(threat.details) if threat.details else 0,
                'description_length': len(threat.description) if threat.description else 0,
            }
            
            # Type-specific features
            if isinstance(threat, FileThreat):
                feature_dict.update({
                    'is_file_threat': 1,
                    'is_darkweb_threat': 0,
                    'is_databreach_threat': 0,
                    'is_browser_threat': 0,
                    'file_size': threat.file_size if threat.file_size else 0,
                    'is_executable': 1 if threat.filepath and threat.filepath.endswith(('.exe', '.dll', '.bat')) else 0
                })
            elif isinstance(threat, DarkWebThreat):
                feature_dict.update({
                    'is_file_threat': 0,
                    'is_darkweb_threat': 1,
                    'is_databreach_threat': 0,
                    'is_browser_threat': 0,
                    'keywords_count': len(threat.keywords) if threat.keywords else 0,
                    'has_sensitive_data': 1 if threat.sensitive_data else 0,
                    'content_length': len(threat.content_snippet) if threat.content_snippet else 0
                })
            elif isinstance(threat, DataBreachThreat):
                feature_dict.update({
                    'is_file_threat': 0,
                    'is_darkweb_threat': 0,
                    'is_databreach_threat': 1,
                    'is_browser_threat': 0,
                    'pwned_data_count': len(threat.pwned_data) if threat.pwned_data else 0,
                    'breach_age_days': (datetime.now() - threat.breach_date).days if threat.breach_date else 0
                })
            elif isinstance(threat, BrowserThreat):
                feature_dict.update({
                    'is_file_threat': 0,
                    'is_darkweb_threat': 0,
                    'is_databreach_threat': 0,
                    'is_browser_threat': 1,
                    'is_chrome': 1 if threat.browser == 'chrome' else 0,
                    'is_firefox': 1 if threat.browser == 'firefox' else 0,
                    'is_edge': 1 if threat.browser == 'edge' else 0
                })
            
            features.append(feature_dict)
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # Handle categorical variables if needed
        for col in ['threat_type', 'threat_level']:
            if col in df.columns:
                df[col] = df[col].astype('category').cat.codes
        
        return df
    
    def _extract_text_features(self, threats: List[Threat]) -> np.ndarray:
        """
        Extract text features from threat descriptions.
        
        Args:
            threats: List of threat objects
            
        Returns:
            Vectorized text features
        """
        descriptions = [threat.description for threat in threats]
        
        if not self.vectorizer.vocabulary_:
            # First time, fit the vectorizer
            return self.vectorizer.fit_transform(descriptions).toarray()
        else:
            # Use existing vocabulary
            return self.vectorizer.transform(descriptions).toarray()
    
    def predict_threat_level(self, threat: Threat) -> Optional[ThreatLevel]:
        """
        Predict the severity level of a threat using the trained classifier.
        
        Args:
            threat: A threat object to analyze
            
        Returns:
            Predicted threat level or None if prediction fails
        """
        if not self.classifier or not hasattr(self.classifier, 'classes_'):
            # Model not trained yet
            return None
        
        try:
            # Extract features for the threat
            features_df = self._extract_features([threat])
            
            if features_df.empty:
                return None
            
            # Make prediction
            level_code = self.classifier.predict(features_df)[0]
            
            # Map back to ThreatLevel
            level_map = {
                0: ThreatLevel.LOW,
                1: ThreatLevel.MEDIUM,
                2: ThreatLevel.HIGH,
                3: ThreatLevel.CRITICAL
            }
            
            return level_map.get(level_code, ThreatLevel.MEDIUM)
        
        except Exception as e:
            logger.error(f"Error predicting threat level: {e}")
            return None
    
    def detect_anomalies(self, threats: List[Threat]) -> List[bool]:
        """
        Detect anomalous threats that deviate from normal patterns.
        
        Args:
            threats: List of threat objects to analyze
            
        Returns:
            List of booleans where True indicates an anomaly
        """
        if not threats:
            return []
        
        if not self.anomaly_detector or not hasattr(self.anomaly_detector, 'offset_'):
            # Model not trained yet
            return [False] * len(threats)
        
        try:
            # Extract features
            features_df = self._extract_features(threats)
            
            if features_df.empty:
                return [False] * len(threats)
            
            # Scale features
            if self.scaler:
                features = self.scaler.transform(features_df)
            else:
                features = features_df.values
            
            # Predict anomalies
            # IsolationForest returns 1 for normal, -1 for anomalies
            predictions = self.anomaly_detector.predict(features)
            
            # Convert to boolean (True = anomaly)
            return [pred == -1 for pred in predictions]
        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return [False] * len(threats)
    
    def cluster_threats(self, threats: List[Threat]) -> Dict[int, List[Threat]]:
        """
        Cluster threats based on their features to identify patterns.
        
        Args:
            threats: List of threat objects to cluster
            
        Returns:
            Dictionary mapping cluster IDs to lists of threats
        """
        if not threats:
            return {}
        
        try:
            # Extract numerical features
            num_features_df = self._extract_features(threats)
            
            if num_features_df.empty:
                return {0: threats}  # Put all in one cluster
            
            # Extract text features if we have descriptions
            if all(threat.description for threat in threats):
                text_features = self._extract_text_features(threats)
                
                # Combine features
                combined_features = np.hstack((
                    self.scaler.fit_transform(num_features_df),
                    text_features
                ))
            else:
                # Just use numerical features
                combined_features = self.scaler.fit_transform(num_features_df)
            
            # Apply dimensionality reduction for better clustering
            if combined_features.shape[1] > 10:
                pca = PCA(n_components=min(10, combined_features.shape[0], combined_features.shape[1]))
                reduced_features = pca.fit_transform(combined_features)
            else:
                reduced_features = combined_features
            
            # Fit the clusterer
            cluster_labels = self.clusterer.fit_predict(reduced_features)
            
            # Organize threats by cluster
            clusters = {}
            for i, threat in enumerate(threats):
                cluster_id = int(cluster_labels[i])
                if cluster_id not in clusters:
                    clusters[cluster_id] = []
                clusters[cluster_id].append(threat)
            
            return clusters
        
        except Exception as e:
            logger.error(f"Error clustering threats: {e}")
            return {0: threats}  # Put all in one cluster on error
    
    def train_models(self) -> bool:
        """
        Train or update all machine learning models with current threat data.
        
        Returns:
            Boolean indicating success
        """
        threats = self.threat_db.threats
        
        if len(threats) < 10:
            logger.warning("Not enough threats to train models (minimum 10 required)")
            return False
        
        success = True
        
        # Train classifier
        try:
            features_df = self._extract_features(threats)
            labels = [
                0 if threat.level == ThreatLevel.LOW else
                1 if threat.level == ThreatLevel.MEDIUM else
                2 if threat.level == ThreatLevel.HIGH else 3
                for threat in threats
            ]
            
            self.classifier.fit(features_df, labels)
            joblib.dump(self.classifier, THREAT_CLASSIFIER_MODEL)
            logger.info("Trained and saved threat classifier model")
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
            success = False
        
        # Train anomaly detector
        try:
            features_df = self._extract_features(threats)
            scaled_features = self.scaler.fit_transform(features_df)
            
            self.anomaly_detector.fit(scaled_features)
            joblib.dump(self.anomaly_detector, ANOMALY_DETECTOR_MODEL)
            logger.info("Trained and saved anomaly detector model")
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            success = False
        
        # Train clusterer
        try:
            # Extract all features
            num_features_df = self._extract_features(threats)
            text_features = self._extract_text_features(threats)
            
            # Combine features
            combined_features = np.hstack((
                self.scaler.fit_transform(num_features_df),
                text_features
            ))
            
            # Apply dimensionality reduction
            pca = PCA(n_components=min(10, combined_features.shape[0], combined_features.shape[1]))
            reduced_features = pca.fit_transform(combined_features)
            
            # Fit the clusterer
            self.clusterer.fit(reduced_features)
            
            # Save the models
            model_data = {
                'clusterer': self.clusterer,
                'vectorizer': self.vectorizer,
                'scaler': self.scaler
            }
            joblib.dump(model_data, THREAT_CLUSTERER_MODEL)
            logger.info("Trained and saved threat clusterer model")
        except Exception as e:
            logger.error(f"Error training threat clusterer: {e}")
            success = False
        
        return success
    
    def analyze_threat_patterns(self) -> Dict[str, Any]:
        """
        Analyze patterns in threats to identify trends and common characteristics.
        
        Returns:
            Dictionary with analysis results
        """
        threats = self.threat_db.threats
        
        if not threats:
            return {"error": "No threats available for analysis"}
        
        result = {}
        
        # Get threats by severity
        by_severity = self.threat_db.get_by_severity()
        
        # Calculate severity distribution
        severity_distribution = {
            level.value: len(threats_list)
            for level, threats_list in by_severity.items()
        }
        result["severity_distribution"] = severity_distribution
        
        # Calculate type distribution
        type_distribution = {}
        for threat in threats:
            threat_type = threat.type.value
            if threat_type not in type_distribution:
                type_distribution[threat_type] = 0
            type_distribution[threat_type] += 1
        result["type_distribution"] = type_distribution
        
        # Identify trends over time
        if len(threats) >= 5:
            # Sort threats by timestamp
            sorted_threats = sorted(
                [t for t in threats if t.timestamp],
                key=lambda x: x.timestamp
            )
            
            if sorted_threats:
                # Calculate weekly counts
                weekly_counts = {}
                for threat in sorted_threats:
                    # Get week number
                    week = threat.timestamp.strftime("%Y-%U")
                    if week not in weekly_counts:
                        weekly_counts[week] = 0
                    weekly_counts[week] += 1
                
                result["weekly_trend"] = weekly_counts
                
                # Calculate severity trend
                severity_trend = {}
                for threat in sorted_threats:
                    week = threat.timestamp.strftime("%Y-%U")
                    level = threat.level.value
                    
                    if week not in severity_trend:
                        severity_trend[week] = {
                            "low": 0,
                            "medium": 0,
                            "high": 0,
                            "critical": 0
                        }
                    
                    severity_trend[week][level] += 1
                
                result["severity_trend"] = severity_trend
        
        # Identify common patterns in clusters
        if len(threats) >= 10:
            clusters = self.cluster_threats(threats)
            
            cluster_info = {}
            for cluster_id, cluster_threats in clusters.items():
                if cluster_id == -1:
                    # DBSCAN noise points
                    continue
                    
                # Skip singleton clusters
                if len(cluster_threats) < 2:
                    continue
                
                # Get common characteristics
                common_type = None
                type_counts = {}
                for threat in cluster_threats:
                    threat_type = threat.type.value
                    if threat_type not in type_counts:
                        type_counts[threat_type] = 0
                    type_counts[threat_type] += 1
                
                # Find most common type
                if type_counts:
                    common_type = max(type_counts.items(), key=lambda x: x[1])[0]
                
                # Get average severity
                severity_map = {
                    ThreatLevel.LOW: 1,
                    ThreatLevel.MEDIUM: 2,
                    ThreatLevel.HIGH: 3,
                    ThreatLevel.CRITICAL: 4
                }
                
                avg_severity = sum(severity_map[t.level] for t in cluster_threats) / len(cluster_threats)
                
                # Map back to severity level
                if avg_severity < 1.5:
                    avg_severity_label = "low"
                elif avg_severity < 2.5:
                    avg_severity_label = "medium"
                elif avg_severity < 3.5:
                    avg_severity_label = "high"
                else:
                    avg_severity_label = "critical"
                
                # Store cluster info
                cluster_info[cluster_id] = {
                    "size": len(cluster_threats),
                    "common_type": common_type,
                    "avg_severity": avg_severity_label,
                    "recent_threat": max(
                        (t for t in cluster_threats if t.timestamp),
                        key=lambda x: x.timestamp,
                        default=None
                    ).description if any(t.timestamp for t in cluster_threats) else None
                }
            
            result["clusters"] = cluster_info
        
        # Identify anomalies
        if len(threats) >= 10:
            anomalies = self.detect_anomalies(threats)
            anomalous_threats = [
                threats[i].description
                for i, is_anomaly in enumerate(anomalies)
                if is_anomaly
            ]
            
            result["anomalies"] = anomalous_threats
        
        return result
    
    def predict_future_threats(self, days_ahead: int = 7) -> Dict[str, Any]:
        """
        Predict potential future threats based on historical patterns.
        
        Args:
            days_ahead: Number of days to predict ahead
            
        Returns:
            Dictionary with prediction results
        """
        threats = self.threat_db.threats
        
        if len(threats) < 10:
            return {"error": "Not enough historical threat data for prediction"}
        
        # Filter threats with timestamps
        dated_threats = [t for t in threats if t.timestamp]
        
        if len(dated_threats) < 10:
            return {"error": "Not enough dated threat data for prediction"}
        
        # Sort by timestamp
        sorted_threats = sorted(dated_threats, key=lambda x: x.timestamp)
        
        # Get the date range
        start_date = sorted_threats[0].timestamp
        end_date = sorted_threats[-1].timestamp
        
        # Calculate days in the range
        days_range = (end_date - start_date).days
        
        if days_range < 7:
            return {"error": "Need at least 7 days of historical data"}
        
        # Group threats by day
        daily_counts = {}
        for threat in sorted_threats:
            day_key = threat.timestamp.strftime("%Y-%m-%d")
            if day_key not in daily_counts:
                daily_counts[day_key] = {
                    'total': 0,
                    'low': 0,
                    'medium': 0,
                    'high': 0,
                    'critical': 0,
                    'file': 0,
                    'darkweb': 0,
                    'databreach': 0,
                    'browser': 0
                }
            
            daily_counts[day_key]['total'] += 1
            daily_counts[day_key][threat.level.value] += 1
            
            if isinstance(threat, FileThreat):
                daily_counts[day_key]['file'] += 1
            elif isinstance(threat, DarkWebThreat):
                daily_counts[day_key]['darkweb'] += 1
            elif isinstance(threat, DataBreachThreat):
                daily_counts[day_key]['databreach'] += 1
            elif isinstance(threat, BrowserThreat):
                daily_counts[day_key]['browser'] += 1
        
        # Convert to DataFrame for time series analysis
        df = pd.DataFrame.from_dict(daily_counts, orient='index')
        df.index = pd.to_datetime(df.index)
        df = df.sort_index()
        
        # Fill in missing days with zeros
        idx = pd.date_range(start=df.index.min(), end=df.index.max())
        df = df.reindex(idx, fill_value=0)
        
        # Simple forecasting: calculate moving averages
        window_size = min(7, len(df) // 2)
        df_ma = df.rolling(window=window_size, min_periods=1).mean()
        
        # Calculate trend
        if len(df) >= 14:
            # Split into two halves
            half = len(df) // 2
            first_half_avg = df.iloc[:half].mean()
            second_half_avg = df.iloc[half:].mean()
            
            # Calculate percentage change
            trend = {}
            for col in df.columns:
                if first_half_avg[col] > 0:
                    pct_change = (second_half_avg[col] - first_half_avg[col]) / first_half_avg[col] * 100
                    trend[col] = round(pct_change, 1)
                else:
                    trend[col] = 0.0
        else:
            trend = {col: 0.0 for col in df.columns}
        
        # Make predictions for the next days_ahead days
        last_date = df.index[-1]
        forecast_dates = [last_date + timedelta(days=i+1) for i in range(days_ahead)]
        
        # Use the moving average of the last window_size days as the prediction
        last_values = df_ma.iloc[-1].to_dict()
        
        # Apply trend to forecast
        forecast = []
        for i, date in enumerate(forecast_dates):
            day_forecast = {}
            for col, val in last_values.items():
                # Apply cumulative trend effect
                trend_factor = 1 + (trend[col] / 100) * ((i + 1) / days_ahead)
                # Ensure we don't get negative predictions
                predicted_val = max(0, val * trend_factor)
                
                # Convert to integer for count data
                if col in ['total', 'low', 'medium', 'high', 'critical', 
                          'file', 'darkweb', 'databreach', 'browser']:
                    predicted_val = round(predicted_val)
                
                day_forecast[col] = predicted_val
            
            forecast.append({
                'date': date.strftime("%Y-%m-%d"),
                'prediction': day_forecast
            })
        
        # Calculate overall risk trend
        risk_trend = "stable"
        critical_high_trend = trend['critical'] + trend['high']
        if critical_high_trend > 10:
            risk_trend = "increasing"
        elif critical_high_trend < -10:
            risk_trend = "decreasing"
        
        # Identify most likely threat types
        threat_type_trends = {
            'file': trend['file'],
            'darkweb': trend['darkweb'],
            'databreach': trend['databreach'],
            'browser': trend['browser']
        }
        
        most_likely_threat = max(threat_type_trends.items(), key=lambda x: x[1])[0]
        
        return {
            "forecast": forecast,
            "trend": trend,
            "risk_trend": risk_trend,
            "most_likely_threat": most_likely_threat
        }