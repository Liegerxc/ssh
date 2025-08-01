#!/bin/bash

# Verifica se é root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script deve ser executado como root. Use sudo ou faça login como root."
  exit 1
fi

echo "➤ Atualizando o sistema..."
apt-get update -y
apt-get upgrade -y

echo "➤ Instalando dependências..."
apt-get install -y apache2 php libapache2-mod-php php-mbstring unzip

echo "➤ Configurando a estrutura de diretórios..."
mkdir -p /var/www/html/open/uploads
chown -R www-data:www-data /var/www/html/open
chmod -R 755 /var/www/html/open
chmod 700 /var/www/html/open/uploads

echo "➤ Criando a página de upload..."
cat > /var/www/html/open/index.php << 'EOL'
<?php
// Configurações
$upload_dir = 'uploads/';
$allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];

// Processar upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    if (in_array($file['type'], $allowed_types)) {
        $target_path = $upload_dir . basename($file['name']);
        
        if (move_uploaded_file($file['tmp_name'], $target_path)) {
            $message = 'Arquivo enviado com sucesso!';
        } else {
            $message = 'Erro ao mover o arquivo.';
        }
    } else {
        $message = 'Tipo de arquivo não permitido.';
    }
}

// Listar arquivos
$files = glob($upload_dir . '*');
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload de Arquivos</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .file-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .file-icon {
            font-size: 3rem;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <div class="max-w-4xl mx-auto bg-white rounded-xl shadow-md overflow-hidden p-6">
            <h1 class="text-3xl font-bold text-gray-800 mb-6">Upload de Arquivos</h1>
            
            <?php if (isset($message)): ?>
                <div class="mb-4 p-4 bg-blue-100 text-blue-800 rounded-lg">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" enctype="multipart/form-data" class="mb-8">
                <div class="flex items-center justify-center w-full">
                    <label for="file" class="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100">
                        <div class="flex flex-col items-center justify-center pt-5 pb-6">
                            <svg class="w-8 h-8 mb-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                            </svg>
                            <p class="mb-2 text-sm text-gray-500">Clique para selecionar ou arraste o arquivo</p>
                            <p class="text-xs text-gray-500">Formatos permitidos: JPG, PNG, GIF, PDF, TXT</p>
                        </div>
                        <input id="file" name="file" type="file" class="hidden" />
                    </label>
                </div>
                <button type="submit" class="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">Enviar Arquivo</button>
            </form>
            
            <h2 class="text-2xl font-semibold text-gray-800 mb-4">Arquivos Disponíveis</h2>
            
            <?php if (empty($files)): ?>
                <p class="text-gray-500">Nenhum arquivo disponível.</p>
            <?php else: ?>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                    <?php foreach ($files as $file): ?>
                        <?php
                        $filename = basename($file);
                        $filepath = $upload_dir . $filename;
                        $filetype = mime_content_type($file);
                        $filesize = filesize($file);
                        $icon = '📄';
                        
                        if (strpos($filetype, 'image/') === 0) $icon = '🖼️';
                        elseif ($filetype === 'application/pdf') $icon = '📕';
                        ?>
                        
                        <div class="file-card bg-white rounded-lg border border-gray-200 p-4 transition duration-300">
                            <div class="text-center mb-2">
                                <span class="file-icon"><?php echo $icon; ?></span>
                            </div>
                            <div class="text-center">
                                <p class="font-medium text-gray-800 truncate"><?php echo htmlspecialchars($filename); ?></p>
                                <p class="text-sm text-gray-500"><?php echo round($filesize / 1024, 2); ?> KB</p>
                                <div class="mt-2 flex justify-center space-x-2">
                                    <a href="<?php echo htmlspecialchars($filepath); ?>" download class="px-3 py-1 bg-green-100 text-green-800 text-sm rounded hover:bg-green-200">Download</a>
                                    <a href="<?php echo htmlspecialchars($filepath); ?>" target="_blank" class="px-3 py-1 bg-blue-100 text-blue-800 text-sm rounded hover:bg-blue-200">Visualizar</a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
EOL

echo "➤ Configurando o firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "➤ Reiniciando o Apache..."
systemctl restart apache2

echo "✅ Instalação concluída com sucesso!"
echo "Acesse sua página de upload em:"
echo "http://$(curl -s ifconfig.me)/open/"
