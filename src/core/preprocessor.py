import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from src.utils.logger import setup_logger

logger = setup_logger("preprocessor")

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # We process packets in "windows" for LSTM (e.g., look at last 10 packets)
        self.sequence_length = 1 
        self.num_features = 8 # Must match your dataset columns

    def fit(self, X):
        """Fit the scaler on training data"""
        self.scaler.fit(X)
        self.is_fitted = True

    def transform(self, X):
        """Scale and reshape data for LSTM"""
        if not self.is_fitted:
            logger.warning("Preprocessor used before fitting! Using dummy fit.")
            self.fit(X)
            
        X_scaled = self.scaler.transform(X)
        
        # Reshape for LSTM: [samples, time_steps, features]
        # Here we treat each packet as a single time-step sequence for simplicity
        # In advanced versions, we group 10 packets into 1 sequence.
        X_reshaped = np.reshape(X_scaled, (X_scaled.shape[0], self.sequence_length, X_scaled.shape[1]))
        
        return X_reshaped

    def clean_and_encode(self, data_dict):
        """
        Real-time pipeline: Dict -> DataFrame -> Scale -> Reshape
        """
        try:
            df = pd.DataFrame([data_dict])
            
            # Simple numeric conversion (ensure all cols exist)
            # In production, use your actual feature columns list here
            df = df.select_dtypes(include=[np.number])
            
            # Fill missing columns with 0 to match training shape
            if df.shape[1] < self.num_features:
                for i in range(self.num_features - df.shape[1]):
                    df[f'dummy_{i}'] = 0
            
            # Use only first 8 columns (to match our dummy training data)
            data_numeric = df.iloc[:, :self.num_features].values
            
            return self.transform(data_numeric)
            
        except Exception as e:
            logger.error(f"Preprocessing error: {e}")
            return None