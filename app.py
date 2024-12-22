import os

import streamlit as st
import pefile
import joblib
import pandas as pd



# Charger le modèle
model = joblib.load("optimized_model.pkl")


# Fonction pour extraire les caractéristiques
def get_resource_size(pe):
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE.entries:
            total_size = 0
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'directory') and entry.directory.entries:
                    for sub_entry in entry.directory.entries:
                        if hasattr(sub_entry, 'data') and hasattr(sub_entry.data, 'struct'):
                            total_size += sub_entry.data.struct.Size
            return total_size
        return 0
    except Exception as e:
        print(f"Erreur lors de l'extraction de la taille des ressources : {e}")
        return 0


def extract_features(executable_path):
    try:
        pe = pefile.PE(executable_path)
        features = {
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'NumberOfSections': len(pe.sections),
            'ResourceSize': get_resource_size(pe)
        }
        return features
    except Exception as e:
        print(f"Erreur lors de l'extraction des caractéristiques : {e}")
        return None


# Interface Streamlit
st.title("Détection de Malware")

uploaded_file = st.file_uploader("Téléversez un fichier exécutable", type=["exe"])

if uploaded_file is not None:
    with open(f"./temp/{uploaded_file.name}", "wb") as f:
        f.write(uploaded_file.getbuffer())
        file_path = f"./temp/{uploaded_file.name}"

    st.write("Analyse du fichier en cours...")
    features = extract_features(file_path)

    if features is None:
        st.error("Erreur lors de l'extraction des caractéristiques.")
    else:
        features_df = pd.DataFrame([features])
        prediction = model.predict(features_df)[0]
        result = "Malware" if prediction == 1 else "Non-Malware"
        st.success(f"Résultat : {result}")