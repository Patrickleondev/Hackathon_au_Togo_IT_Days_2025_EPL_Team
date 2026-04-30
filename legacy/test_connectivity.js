// Test de connectivité entre frontend et backend
const API_BASE_URL = 'http://localhost:8000';

async function testConnectivity() {
    console.log('🔍 Test de connectivité vers le backend...');
    
    try {
        // Test 1: Endpoint de santé
        const healthResponse = await fetch(`${API_BASE_URL}/api/health`);
        if (healthResponse.ok) {
            const healthData = await healthResponse.json();
            console.log('✅ Backend accessible:', healthData);
        } else {
            console.log('❌ Backend non accessible:', healthResponse.status);
        }
    } catch (error) {
        console.log('❌ Erreur de connexion:', error.message);
    }
    
    try {
        // Test 2: Status des modèles
        const modelsResponse = await fetch(`${API_BASE_URL}/api/models/status`);
        if (modelsResponse.ok) {
            const modelsData = await modelsResponse.json();
            console.log('✅ Modèles status:', modelsData);
        } else {
            console.log('❌ Erreur modèles:', modelsResponse.status);
        }
    } catch (error) {
        console.log('❌ Erreur modèles:', error.message);
    }
}

// Exécuter le test
testConnectivity();
