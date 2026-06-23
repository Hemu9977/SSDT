import { useState } from 'react';
import ParticleBackground from './ParticleBackground';
import '../styles/SplashScreen.scss';

const SplashScreen = ({ onEnter }) => {
  const [showButton, setShowButton] = useState(true);

  const handleEnter = () => {
    // Play the sound
    const audio = document.getElementById('splash-sound');
    if (audio) {
      audio.play().catch(err => {
        console.log('Audio playback failed:', err);
      });
    }

    // Hide button and trigger fade out
    setShowButton(false);

    // Call the onEnter callback after a short delay
    setTimeout(() => {
      onEnter();
    }, 1000); // Wait for fade animation
  };

  return (
    <div id="splash-screen">
      <ParticleBackground />
      <div className="splash-content">
        <img
          src={`${process.env.PUBLIC_URL}/logo.png`}
          alt="SSDT Security Scanner Logo"
          className="splash-logo"
        />
        <h1 className="splash-title">Fortexa</h1>
        <p className="splash-subtitle">Security Scanner Detection Tool</p>

        {showButton && (
          <button
            className="splash-enter-btn"
            onClick={handleEnter}
          >
            Click to Enter
          </button>
        )}
      </div>
    </div>
  );
};

export default SplashScreen;
