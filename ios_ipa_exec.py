import zipfile
import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Toplevel, Text, Scrollbar


def format_size(size):
    for unit in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024


def get_file_sizes_from_zip(zip_path):
    file_sizes = []
    with zipfile.ZipFile(zip_path, 'r') as zip_file:
        for file_info in zip_file.infolist():
            file_size = file_info.file_size
            file_sizes.append((file_info.filename, file_size))
    file_sizes.sort(key=lambda x: x[1], reverse=True)
    return file_sizes


def get_file_sizes_from_dir(dir_path):
    file_sizes = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            relative_path = os.path.relpath(file_path, dir_path)
            file_sizes.append((relative_path, file_size))
    file_sizes.sort(key=lambda x: x[1], reverse=True)
    return file_sizes


def analyze_app(app_path):
    if os.path.isfile(app_path) and app_path.endswith('.ipa'):
        file_sizes = get_file_sizes_from_zip(app_path)
    elif os.path.isdir(app_path):
        file_sizes = get_file_sizes_from_dir(app_path)
    else:
        messagebox.showerror("Erro", f"{app_path} não é um arquivo ou diretório válido.")
        return None, None
    total_size = sum(size for _, size in file_sizes)
    return file_sizes, total_size


def browse_file_or_directory():
    path = filedialog.askopenfilename(
        filetypes=[("iOS App Files", "*.ipa"), ("iOS App Files", "*.app"), ("Directories", "*/")])
    if path:
        entry_path.delete(0, tk.END)
        entry_path.insert(0, path)


def start_analysis():
    app_path = entry_path.get()
    if not app_path:
        messagebox.showwarning("Aviso", "Por favor, selecione um arquivo .ipa ou diretório .app.")
        return

    file_sizes, total_size = analyze_app(app_path)
    if file_sizes is None:
        return

    for item in tree.get_children():
        tree.delete(item)

    for file, size in file_sizes:
        tree.insert("", "end", values=(file, format_size(size)))

    label_total_size.config(text=f"Tamanho total: {format_size(total_size)}")

    large_files = [f"{file}: {format_size(size)}" for file, size in file_sizes if size > 10 * 1024 * 1024]
    report = "Arquivos maiores que 10 MB:\n" + "\n".join(
        large_files) if large_files else "Nenhum arquivo maior que 10 MB encontrado."
    text_report.config(state=tk.NORMAL)
    text_report.delete(1.0, tk.END)
    text_report.insert(tk.END, report)
    text_report.config(state=tk.DISABLED)


def extract_executable_from_ipa(ipa_path, executable_name):
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith(executable_name):
                extracted_path = os.path.join(os.path.dirname(ipa_path), executable_name)
                zip_ref.extract(file, os.path.dirname(ipa_path))
                return os.path.join(os.path.dirname(ipa_path), file)
    return None


def list_executable_info(file_path):
    try:
        file_output = subprocess.check_output(['file', file_path]).decode('utf-8')
        if 'executable' in file_output.lower() or 'library' in file_output.lower():
            otool_output = subprocess.check_output(['otool', '-L', file_path]).decode('utf-8')
            size_output = subprocess.check_output(['size', '-m', file_path]).decode('utf-8')
            nm_output = subprocess.check_output(['nm', file_path]).decode('utf-8')
            strings_output = subprocess.check_output(['strings', file_path]).decode('utf-8')

            # Salvar nm_output e strings_output em arquivos .txt
            nm_output_file = os.path.join(os.path.dirname(file_path), 'nm_output.txt')
            strings_output_file = os.path.join(os.path.dirname(file_path), 'strings_output.txt')

            with open(nm_output_file, 'w') as nm_file:
                nm_file.write(nm_output)

            with open(strings_output_file, 'w') as strings_file:
                strings_file.write(strings_output)

            show_executable_info(file_output, otool_output, size_output, nm_output_file, strings_output_file)
        else:
            messagebox.showinfo("Informação", "O arquivo selecionado não é um executável Unix.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao listar informações do executável: {str(e)}")


def show_executable_info(file_output, otool_output, size_output, nm_output_file, strings_output_file):
    info_window = Toplevel(root)
    info_window.title("Informações do Executável")
    info_window.geometry("800x600")

    text_widget = Text(info_window, wrap=tk.WORD)
    text_widget.insert(tk.END, f"Informações do arquivo:\n{file_output}\n\n")
    text_widget.insert(tk.END, f"Dependências do executável (otool -L):\n{otool_output}\n\n")

    text_widget.insert(tk.END, "Tamanho das seções do executável (size):\n")
    text_widget.insert(tk.END, format_size_output(size_output))

    text_widget.insert(tk.END, f"\nOs resultados do comando 'nm' foram salvos em: {nm_output_file}\n")
    text_widget.insert(tk.END, f"Os resultados do comando 'strings' foram salvos em: {strings_output_file}\n")

    text_widget.config(state=tk.DISABLED)

    scrollbar = Scrollbar(info_window, command=text_widget.yview)
    text_widget.config(yscrollcommand=scrollbar.set)

    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


def format_size_output(size_output):
    lines = size_output.strip().split('\n')
    sections = {}
    current_segment = None
    for line in lines:
        if line.startswith("Segment"):
            parts = line.split()
            current_segment = parts[1][:-1]
            segment_size = int(parts[2])
            sections[current_segment] = [("total", segment_size)]
        elif current_segment and line.startswith("\tSection"):
            parts = line.split()
            section_name = parts[1][:-1]
            section_size = int(parts[2])
            sections[current_segment].append((section_name, section_size))
        elif line.startswith("total"):
            break  # Ignore the total line

    formatted_output = "Detalhes das seções e segmentos:\n"
    total_size = 0
    for segment, sec_list in sections.items():
        if segment != "__PAGEZERO":  # Ignorar o segmento __PAGEZERO
            segment_total = sec_list[0][1]
            formatted_output += f"{segment}: {format_size(segment_total)}\n"
            total_size += segment_total
            for sec_name, sec_size in sec_list[1:]:
                formatted_output += f"    {sec_name}: {sec_size} Bytes ({format_size(sec_size)})\n"
            formatted_output += "\n"

    formatted_output += f"Tamanho total (excluindo __PAGEZERO): {format_size(total_size)}\n"
    return formatted_output


def on_item_double_click(event):
    selected_item = tree.selection()[0]
    relative_path = tree.item(selected_item)['values'][0]
    app_path = entry_path.get()

    if os.path.isdir(app_path):
        file_path = os.path.join(app_path, relative_path)
    elif app_path.endswith('.ipa'):
        executable_name = os.path.basename(relative_path)
        file_path = extract_executable_from_ipa(app_path, executable_name)
        if file_path is None:
            messagebox.showinfo("Informação", "Executável não encontrado no arquivo .ipa.")
            return
    else:
        file_path = os.path.join(app_path, relative_path)

    if os.path.isfile(file_path):
        list_executable_info(file_path)
    else:
        messagebox.showinfo("Informação", "Por favor, selecione um executável Unix para visualizar mais informações.")


root = tk.Tk()
root.title("Analisador de Tamanho de App iOS")

frame_path = ttk.Frame(root)
frame_path.pack(padx=10, pady=10, fill=tk.X)

label_path = ttk.Label(frame_path, text="Selecione o arquivo .ipa ou diretório .app:")
label_path.pack(side=tk.LEFT)

entry_path = ttk.Entry(frame_path, width=50)
entry_path.pack(side=tk.LEFT, padx=5)

button_browse = ttk.Button(frame_path, text="Procurar", command=browse_file_or_directory)
button_browse.pack(side=tk.LEFT)

button_analyze = ttk.Button(root, text="Analisar", command=start_analysis)
button_analyze.pack(pady=10)

columns = ("Arquivo", "Tamanho")
tree = ttk.Treeview(root, columns=columns, show="headings")
tree.heading("Arquivo", text="Arquivo")
tree.heading("Tamanho", text="Tamanho")
tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
tree.bind("<Double-1>", on_item_double_click)

label_total_size = ttk.Label(root, text="Tamanho total: ")
label_total_size.pack(pady=5)

text_report = tk.Text(root, height=10, state=tk.DISABLED)
text_report.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()
