import requests

class VirusTotalScan:
    def __init__(self, api_key, file_path):
        self.api_key = api_key
        self.file_path = file_path
        self.url = 'https://www.virustotal.com/vtapi/v2/file/report'
        
    def check_scan_status(self):
        params = {'apikey': self.api_key, 'resource': self.file_path}
        response = requests.get(self.url, params=params)
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            print(f"El archivo {self.file_path} tiene un total de {total} detecciones.")
            print(f"{positives} de los antivirus analizados detectaron el archivo como malicioso.")
        else:
            print("El archivo no fue encontrado en la base de datos de VirusTotal.")













