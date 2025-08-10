import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const resources = {
  fr: {
    translation: {
      nav: {
        dashboard: 'Tableau de bord',
        upload: 'Analyse de fichier',
        threats: 'Menaces détectées',
        scan: 'Scanner le système',
        statistics: 'Statistiques',
        settings: 'Paramètres'
      },
      titles: {
        dashboard: 'Tableau de bord',
        upload: 'Analyse de fichiers',
        threats: 'Menaces détectées',
        scan: 'Scanner le système',
        statistics: 'Statistiques',
        settings: 'Paramètres'
      }
    }
  },
  en: {
    translation: {
      nav: {
        dashboard: 'Dashboard',
        upload: 'File analysis',
        threats: 'Detected threats',
        scan: 'System scan',
        statistics: 'Statistics',
        settings: 'Settings'
      },
      titles: {
        dashboard: 'Dashboard',
        upload: 'File analysis',
        threats: 'Detected threats',
        scan: 'System scan',
        statistics: 'Statistics',
        settings: 'Settings'
      }
    }
  },
  ee: {
    translation: {
      nav: {
        dashboard: 'Akɔntabibiwo kɔkɔe',
        upload: 'Fayilo nuŋlɔdzi',
        threats: 'Aʋawɔnuwo ɖe',
        scan: 'Sisteme dziɖuɖu',
        statistics: 'Akɔntabisisiwo',
        settings: 'Nustɔwo'
      },
      titles: {
        dashboard: 'Akɔntabibiwo kɔkɔe',
        upload: 'Fayilo nuŋlɔdzi',
        threats: 'Aʋawɔnuwo ɖe',
        scan: 'Sisteme dziɖuɖu',
        statistics: 'Akɔntabisisiwo',
        settings: 'Nustɔwo'
      }
    }
  }
};

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: 'fr',
    fallbackLng: 'fr',
    interpolation: { escapeValue: false }
  });

export default i18n;