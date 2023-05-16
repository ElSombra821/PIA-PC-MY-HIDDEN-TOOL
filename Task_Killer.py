import psutil

def kill_process(process_num):
    # Obtener la lista de procesos y sus detalles
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append(proc.info)

    # Comprobar si el número de proceso es válido
    if process_num <= 0 or process_num > len(processes):
        print("Número de proceso inválido. Por favor ingrese un número válido.")
        return

    # Matar el proceso seleccionado
    pid = processes[process_num-1]['pid']
    psutil.Process(pid).kill()
    print(f"Proceso con PID {pid} ha sido detenido.")
