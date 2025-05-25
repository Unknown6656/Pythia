import * as React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import MainPage from './main.jsx';


const web_root = document.getElementsByTagName('page-root')[0];


ReactDOM.createRoot(web_root).render(
    <React.StrictMode>
        <Router>
            <Routes>
                <Route path='*' element={null}/>
                <Route path="/" element={<MainPage/>}/>
            </Routes>
        </Router>
    </React.StrictMode>
);

document.documentElement.setAttribute('loaded', '');
