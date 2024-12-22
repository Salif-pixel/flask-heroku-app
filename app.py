import os

from flask import Flask, request, jsonify
import pefile
import joblib
import pandas as pd

app = Flask(__name__)

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


@app.route('/')
def home():
    print("Page d'accueil appelée")
    return "Flask est en ligne!"


@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Vérifier si un fichier a été envoyé
        if 'file' not in request.files:
            return jsonify({"error": "Aucun fichier envoyé"}), 400

        # Obtenir le fichier uploadé
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Aucun fichier sélectionné"}), 400

        file_path = f"./uploaded_files/{file.filename}"

        # Créer le dossier 'uploaded_files' s'il n'existe pas
        if not os.path.exists('./uploaded_files'):
            os.makedirs('./uploaded_files')

        file.save(file_path)

        # Extraire les caractéristiques (mettre ici ta fonction d'extraction)
        features = extract_features(file_path)

        if features is None:
            return jsonify({"error": "Erreur lors de l'extraction des caractéristiques"}), 400

        # Convertir en DataFrame
        features_df = pd.DataFrame([features])

        # Faire la prédiction
        prediction = model.predict(features_df)[0]
        result = "Ce fichier est un Malware" if prediction == 1 else "Ce fichier n'est pas un Malware"
        return jsonify({"result": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5001)
