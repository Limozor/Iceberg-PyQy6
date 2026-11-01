import time
import requests
from INFO import VirusTotal_API


class VirusTotalScanner:
    def init(self, api_key):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    def upload_file(self, file_path):
        with open(file_path, "rb") as file:
            response = requests.post(
                f"{self.base_url}/files",
                files={"file": file},
                headers=self.headers
            )

        if response.status_code != 200:
            raise Exception(f"Ошибка загрузки: {response.status_code}\n{response.text}")

        return response.json()["data"]["id"]

    def get_analysis_report(self, analysis_id):
        url = f"{self.base_url}/analyses/{analysis_id}"

        for _ in range(10):
            response = requests.get(url, headers=self.headers)
            if response.status_code != 200:
                time.sleep(10)
                continue

            report_data = response.json().get("data", {})
            attributes = report_data.get("attributes", {})
            status = attributes.get("status")

            if status == "completed":
                stats = attributes.get("stats", {})
                results = attributes.get("results", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                is_malicious = malicious > 0
                is_suspicious = suspicious > 0

                # Возврат словарей stats и results для обработки в Master_Algorithm.py
                # Индексы: [0] - Ошибка, [1] - Опасен, [2] - Подозрителен, [3] - stats, [4] - results
                return [False, is_malicious, is_suspicious, stats, results]

            elif status in ["queued", "in_progress"]:
                time.sleep(15)
            elif status == "failed":
                raise Exception("Анализ завершился с ошибкой.")
            else:
                raise Exception(f"Неожиданный статус: {status}")

        raise Exception("Превышено время ожидания анализа.")                                                                       #Каз, нел пом

    def scan_file(self, file_path):
        try:
            analysis_id = self.upload_file(file_path)
            return self.get_analysis_report(analysis_id)
        except Exception as e:
            #[0] = True - произошла ошибка на стороне API/сети
            return [True, False, False, f"Ошибка при работе с VirusTotal: {str(e)}"]


def Virus_Total_Scan(file_path):
    scanner = VirusTotalScanner(VirusTotal_API)
    return scanner.scan_file(file_path)