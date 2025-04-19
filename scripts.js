// Get time
function showTime() {
    const now = new Date();
    document.getElementById("time").innerHTML = now.toLocaleTimeString();
}

setInterval(showTime, 1000); // Update every second

// Get the sidebar and content
const sidebar = document.getElementById('sidebar');
const content = document.querySelector('.content');
const navbar = document.querySelector('.navbar');
const header = document.querySelector('.header'); // Add this line

// Function to show sidebar when mouse is on the left edge
document.addEventListener('mousemove', (event) => {
    if (event.clientX <= 50) {
        sidebar.classList.add('active');
        content.style.marginLeft = '250px';
        navbar.style.marginLeft = '250px';
        header.style.marginLeft = '250px'; // Add this line
    } else {
        sidebar.classList.remove('active');
        content.style.marginLeft = '0';
        navbar.style.marginLeft = '0';
        header.style.marginLeft = '0'; // Add this line
    }
});
