#Importamos nuestras librerias
import psutil
import requests
import argparse


#Importamos nuestros modulos
from Cifrado_Cesar import cifradoCesar
from Descifrado_Cesar import descifradoCesar
from HASH import HashTool
from VirusTotal import VirusTotalScan
from Task_Killer import kill_process


#Ponemos el nombre de la herrramienta con fines de estetica
texto = """
███╗░░░███╗██╗░░░██╗  ██╗░░██╗██╗██████╗░██████╗░███████╗███╗░░██╗  ████████╗░█████╗░░█████╗░██╗░░░░░
████╗░████║╚██╗░██╔╝  ██║░░██║██║██╔══██╗██╔══██╗██╔════╝████╗░██║  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░
██╔████╔██║░╚████╔╝░  ███████║██║██║░░██║██║░░██║█████╗░░██╔██╗██║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
██║╚██╔╝██║░░╚██╔╝░░  ██╔══██║██║██║░░██║██║░░██║██╔══╝░░██║╚████║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
██║░╚═╝░██║░░░██║░░░  ██║░░██║██║██████╔╝██████╔╝███████╗██║░╚███║  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗
╚═╝░░░░░╚═╝░░░╚═╝░░░  ╚═╝░░╚═╝╚═╝╚═════╝░╚═════╝░╚══════╝╚═╝░░╚══╝  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝ v0.0
"""
print(texto)


# Creamos un párrafo de informacion para -h
info = ("\nOpciones:"
        "\nPara el cifrado de un mensaje utilice -c"
        "\nPara el descifrado de un mensaje utilice -d"
        "\nPara generar un hash de un archivo utilice -hash"
        "\nPara analizar un archivo en VirusTotal utilice -virus"
        "\nPara Listar los procesos vivos utilice -l"
        "\nPara matar un proceso utilice -kill")

# Definimos los argumentos aceptados con -h
parser = argparse.ArgumentParser(info)
parser.add_argument('-c', '--cifrado', type=str,
                    help="Mensaje que desea cifrar")
parser.add_argument('-d', '--descifrado', type=str,
                    help="Nombre del archivo con el mensaje que desea descifrar")
parser.add_argument('-hash', '--hash', type=str,
                    help="Generar un hash del archivo especificado")
parser.add_argument('-virus', '--virus', type=str,
                    help="Analizar un archivo en VirusTotal")
parser.add_argument('-api', '--api_key', type=str,
                    help="API key de VirusTotal")
parser.add_argument('-kill', '--kill', type=int,
                    help="Matar un proceso con el número de proceso de la lista")
parser.add_argument('-l', '--list', action='store_true',
                    help="Mostrar una lista de procesos vivos")


# Llamamos a las funciones deseadas de acuerdo a los parámetros que creamos
args = parser.parse_args()

if args.cifrado is not None:
    cifradoCesar(args.cifrado)

if args.descifrado is not None:
    descifradoCesar(args.descifrado)

if args.hash is not None:
    HashTool(args.hash)

if args.virus is not None:
    if args.api_key is not None:
        vt = VirusTotalScan(api_key=args.api_key, file_path=args.virus)
    else:
        vt = VirusTotalScan(api_key='TU_API_KEY', file_path=args.virus)
    vt.check_scan_status()

if args.list:
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append(proc.info)
    print("Procesos vivos:")
    for i, proc in enumerate(processes):
        print(f"{i+1}. PID: {proc['pid']}, Nombre: {proc['name']}")

if args.kill is not None:
    kill_process(args.kill)

