import * as React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import { MainPageWrapper } from './main.jsx';


ReactDOM.createRoot(document.documentElement).render(
    <React.StrictMode>
        <Router>
            <Routes>
                {/* TODO : add other routes and 404 page
                <Route path='*' element={null}/>
                */}
                <Route path="/" element={<MainPageWrapper/>}/>
            </Routes>
        </Router>
    </React.StrictMode>
);

document.documentElement.setAttribute('loaded', '');
